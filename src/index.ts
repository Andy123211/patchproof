import * as core from "@actions/core";
import * as github from "@actions/github";
import { spawn } from "node:child_process";

const MAX_ANNOTATIONS = 30;
const MAX_SUMMARY_ROWS = 250;
const CREDENTIAL_ENVIRONMENT_NAME = /(?:token|secret|password|passwd|credential|private.?key|access.?key|auth)/i;
const ACTION_CONTROL_FILE_ENVIRONMENT_NAMES = new Set([
  "GITHUB_ENV",
  "GITHUB_OUTPUT",
  "GITHUB_PATH",
  "GITHUB_STEP_SUMMARY",
  "GITHUB_STATE",
]);
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/i;

const SECRET_PATTERNS = [
  { name: "Private key block", pattern: PRIVATE_KEY_PATTERN },
  { name: "AWS access key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  {
    name: "Credential-like assignment",
    pattern: /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{16,}/i,
  },
];

const HIGH_RISK_PATH_RULES = [
  { name: "GitHub workflow or action configuration", pattern: /^\.github\/(?:workflows|actions)\//i },
  { name: "Repository ownership or security policy", pattern: /(^|\/)(?:CODEOWNERS|SECURITY\.md)$/i },
  { name: "Repository automation configuration", pattern: /^\.github\/(?:dependabot\.ya?ml|release(?:-please)?(?:\.ya?ml|\.json))$/i },
  {
    name: "Dependency manifest or lockfile",
    pattern: /(^|\/)(?:package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|Cargo\.(?:toml|lock)|go\.(?:mod|sum))$/i,
  },
  {
    name: "Build, deployment, or infrastructure configuration",
    pattern: /(^|\/)(?:Dockerfile(?:\.[^/]*)?|Makefile|Jenkinsfile|action\.ya?ml|docker-compose(?:\.[^/]*)?\.ya?ml|compose\.ya?ml|serverless\.ya?ml|cloudbuild\.ya?ml|[^/]+\.tf)$/i,
  },
  { name: "Environment, package, or authentication configuration", pattern: /(^|\/)(?:\.npmrc|\.env(?:\.[^/]*)?|[^/]*(?:auth|permission|secret|deploy)[^/]*\.ya?ml)$/i },
];

interface ChangedFile {
  filename: string;
  status: string;
  patch?: string;
}

interface SecretFinding {
  file: string;
  line: number;
  patternName: string;
}

interface RiskFinding {
  file: string;
  ruleName: string;
}

interface AddedLine {
  lineNumber: number;
  text: string;
}

interface CheckResult {
  name: string;
  succeeded: boolean;
  exitCode: number | null;
}

interface CheckCommand {
  name: "test" | "lint" | "build";
  command: string;
}

/** Extract added lines and their new-file line numbers from a unified diff patch. */
function getAddedLines(patch: string): AddedLine[] {
  const addedLines: AddedLine[] = [];
  let newLineNumber = 0;

  for (const line of patch.split(/\r?\n/)) {
    const hunkMatch = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunkMatch !== null) {
      newLineNumber = Number(hunkMatch[1]);
      continue;
    }

    if (line.startsWith("+++") || line.startsWith("\\")) {
      continue;
    }

    if (line.startsWith("+")) {
      addedLines.push({ lineNumber: newLineNumber, text: line.slice(1) });
      newLineNumber += 1;
      continue;
    }

    if (line.startsWith(" ")) {
      newLineNumber += 1;
    }
  }

  return addedLines;
}

function findSecretPatterns(files: ChangedFile[]): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const file of files) {
    if (file.patch === undefined) {
      continue;
    }

    for (const addedLine of getAddedLines(file.patch)) {
      for (const secretPattern of SECRET_PATTERNS) {
        if (secretPattern.pattern.test(addedLine.text)) {
          findings.push({ file: file.filename, line: addedLine.lineNumber, patternName: secretPattern.name });
        }
      }
    }
  }

  return findings;
}

function findHighRiskPaths(files: ChangedFile[]): RiskFinding[] {
  const findings: RiskFinding[] = [];

  for (const file of files) {
    const matchingRule = HIGH_RISK_PATH_RULES.find((rule) => rule.pattern.test(file.filename));
    if (matchingRule !== undefined) {
      findings.push({ file: file.filename, ruleName: matchingRule.name });
    }
  }

  return findings;
}

function getSafeChildEnvironment(): NodeJS.ProcessEnv {
  const safeEnvironment: NodeJS.ProcessEnv = {};

  for (const [name, value] of Object.entries(process.env)) {
    const normalizedName = name.toUpperCase();
    if (
      value === undefined ||
      ACTION_CONTROL_FILE_ENVIRONMENT_NAMES.has(normalizedName) ||
      normalizedName.startsWith("ACTIONS_") ||
      normalizedName.startsWith("INPUT_") ||
      CREDENTIAL_ENVIRONMENT_NAME.test(name)
    ) {
      continue;
    }

    safeEnvironment[name] = value;
  }

  return safeEnvironment;
}

function runCheck(name: CheckCommand["name"], command: string, cwd: string): Promise<CheckResult> {
  return new Promise((resolve) => {
    core.info(`Running configured ${name} check.`);

    let childProcess;
    try {
      childProcess = spawn(command, [], {
        cwd,
        env: getSafeChildEnvironment(),
        shell: true,
        stdio: "inherit",
        windowsHide: true,
      });
    } catch {
      core.warning(`The configured ${name} check could not be started.`);
      resolve({ name, succeeded: false, exitCode: null });
      return;
    }

    let spawnFailed = false;
    childProcess.once("error", () => {
      spawnFailed = true;
      core.warning(`The configured ${name} check could not be started.`);
    });

    childProcess.once("close", (exitCode) => {
      const succeeded = !spawnFailed && exitCode === 0;
      if (succeeded) {
        core.info(`Configured ${name} check passed.`);
      } else {
        core.warning(`Configured ${name} check failed${exitCode === null ? "" : ` with exit code ${exitCode}`}.`);
      }

      resolve({ name, succeeded, exitCode });
    });
  });
}

function escapeMarkdownCell(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "&#124;")
    .replace(/`/g, "&#96;")
    .replace(/\r?\n/g, " ");
}

function addTable(summary: typeof core.summary, rows: string[][]): void {
  const safeRows = rows.map((row) => row.map(escapeMarkdownCell));
  summary.addTable(safeRows);
}

function addFindingAnnotations(secretFindings: SecretFinding[], riskFindings: RiskFinding[]): void {
  let annotationCount = 0;

  for (const finding of secretFindings) {
    if (annotationCount >= MAX_ANNOTATIONS) {
      break;
    }

    core.warning(`Possible sensitive value pattern found (${finding.patternName}). Review it without copying the value into logs.`, {
      file: finding.file,
      startLine: finding.line,
      endLine: finding.line,
    });
    annotationCount += 1;
  }

  for (const finding of riskFindings) {
    if (annotationCount >= MAX_ANNOTATIONS) {
      break;
    }

    core.warning(`High-risk repository change: ${finding.ruleName}. Review its trust and permission impact.`, {
      file: finding.file,
    });
    annotationCount += 1;
  }

  const totalFindings = secretFindings.length + riskFindings.length;
  if (totalFindings > annotationCount) {
    core.info(`Annotations were capped at ${MAX_ANNOTATIONS}; the summary reports all findings.`);
  }
}

async function writeSummary(
  files: ChangedFile[],
  secretFindings: SecretFinding[],
  riskFindings: RiskFinding[],
  checkResults: CheckResult[],
): Promise<void> {
  const summary = core.summary;
  const patchAvailableCount = files.filter((file) => file.patch !== undefined).length;
  const rows: string[][] = [
    ["Check", "Result", "Details"],
    ["Changed files", String(files.length), "Files returned by the GitHub pull request API"],
    ["Patch availability", `${patchAvailableCount}/${files.length}`, "Some binary or large-file diffs may not include patch text"],
    ["Sensitive patterns", String(secretFindings.length), "Known patterns found on added diff lines only"],
    ["High-risk paths", String(riskFindings.length), "Changed workflow, dependency, build, ownership, or security configuration"],
  ];

  for (const result of checkResults) {
    rows.push([
      `${result.name} command`,
      result.succeeded ? "Passed" : "Failed",
      result.exitCode === null ? "Could not start" : `Exit code ${result.exitCode}`,
    ]);
  }

  let detailRowCount = 0;
  for (const finding of secretFindings) {
    if (detailRowCount >= MAX_SUMMARY_ROWS) {
      break;
    }
    rows.push(["Sensitive pattern", finding.patternName, `${finding.file}:${finding.line}`]);
    detailRowCount += 1;
  }

  for (const finding of riskFindings) {
    if (detailRowCount >= MAX_SUMMARY_ROWS) {
      break;
    }
    rows.push(["High-risk path", finding.ruleName, finding.file]);
    detailRowCount += 1;
  }

  if (secretFindings.length + riskFindings.length > detailRowCount) {
    rows.push(["Additional findings", "Omitted from detail table", "Counts above include every finding"]);
  }

  summary
    .addHeading("PatchProof evidence report", 2)
    .addRaw("<p>PatchProof reports evidence from this pull request. It does not approve, reject, or comment on the pull request.</p>\n")
    .addTable(rows)
    .addHeading("Scan limits", 3)
    .addList([
      "Sensitive-value checks inspect added lines from patch text returned by GitHub; missing patch text, binary files, and truncated diffs are not scanned.",
      "Pattern checks can produce false positives or miss unknown credential formats. Review findings with a secret scanner and rotate any exposed credential.",
      "High-risk paths are heuristic review prompts, not proof that a change is unsafe.",
    ]);

  if (files.length === 0) {
    summary.addRaw("<p>No changed files were returned for this pull request.</p>\n");
  }

  await summary.write();
}

function getPullRequestNumber(): number {
  if (github.context.eventName !== "pull_request") {
    throw new Error("PatchProof supports the pull_request event only. Do not run it with pull_request_target.");
  }

  const pullRequestNumber = github.context.payload.pull_request?.number;
  if (typeof pullRequestNumber !== "number" || !Number.isInteger(pullRequestNumber)) {
    throw new Error("The pull_request event payload did not contain a valid pull request number.");
  }

  return pullRequestNumber;
}

async function getChangedFiles(token: string, pullRequestNumber: number): Promise<ChangedFile[]> {
  const { owner, repo } = github.context.repo;
  if (!owner || !repo) {
    throw new Error("The GitHub repository context is incomplete.");
  }

  const client = github.getOctokit(token);
  const files: ChangedFile[] = await client.paginate(
    client.rest.pulls.listFiles,
    {
    owner,
    repo,
    pull_number: pullRequestNumber,
    per_page: 100,
    },
  );

  return files.map((file: ChangedFile) => ({ filename: file.filename, status: file.status, patch: file.patch }));
}

async function main(): Promise<void> {
  const pullRequestNumber = getPullRequestNumber();
  const githubToken = core.getInput("github-token", { required: true });
  const failOnSecrets = core.getBooleanInput("fail-on-secrets");
  const failOnRiskyPaths = core.getBooleanInput("fail-on-risky-paths");
  const repositoryPath = process.env.GITHUB_WORKSPACE;

  if (repositoryPath === undefined || repositoryPath.length === 0) {
    throw new Error("GITHUB_WORKSPACE is not available. Run PatchProof in a GitHub Actions job with a checked-out workspace.");
  }

  let files: ChangedFile[];
  try {
    files = await getChangedFiles(githubToken, pullRequestNumber);
  } catch (error) {
    core.debug(error instanceof Error ? error.message : String(error));
    throw new Error("Could not read pull request files. Confirm the token has pull-requests: read permission.");
  }

  const secretFindings = findSecretPatterns(files);
  const riskFindings = findHighRiskPaths(files);
  const checkCommands: CheckCommand[] = [];
  const testCommand = core.getInput("test-command");
  const lintCommand = core.getInput("lint-command");
  const buildCommand = core.getInput("build-command");

  if (testCommand.trim().length > 0) {
    checkCommands.push({ name: "test", command: testCommand });
  }
  if (lintCommand.trim().length > 0) {
    checkCommands.push({ name: "lint", command: lintCommand });
  }
  if (buildCommand.trim().length > 0) {
    checkCommands.push({ name: "build", command: buildCommand });
  }

  const checkResults: CheckResult[] = [];
  for (const checkCommand of checkCommands) {
    checkResults.push(await runCheck(checkCommand.name, checkCommand.command, repositoryPath));
  }

  addFindingAnnotations(secretFindings, riskFindings);
  await writeSummary(files, secretFindings, riskFindings, checkResults);

  core.setOutput("changed-files", String(files.length));
  core.setOutput("secret-findings", String(secretFindings.length));
  core.setOutput("high-risk-paths", String(riskFindings.length));

  const failedChecks = checkResults.some((result) => !result.succeeded);
  const blockingFindings = (failOnSecrets && secretFindings.length > 0) || (failOnRiskyPaths && riskFindings.length > 0);

  if (failedChecks || blockingFindings) {
    const reasons: string[] = [];
    if (failedChecks) {
      reasons.push("one or more configured checks failed");
    }
    if (failOnSecrets && secretFindings.length > 0) {
      reasons.push("sensitive-value patterns were found");
    }
    if (failOnRiskyPaths && riskFindings.length > 0) {
      reasons.push("high-risk paths changed");
    }
    core.setFailed(`PatchProof failed because ${reasons.join(" and ")}. See the step summary for details.`);
  }
}

main().catch((error: unknown) => {
  core.setFailed(error instanceof Error ? error.message : "PatchProof failed with an unknown error.");
});
