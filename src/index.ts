import * as core from "@actions/core";
import * as github from "@actions/github";
import {
  DEFAULT_COMMAND_TIMEOUT_MINUTES,
  parseCommandTimeoutMinutes,
  runShellCommand,
} from "./commands.js";
import { sanitizeChildEnvironment } from "./safety.js";
import {
  MAX_GITHUB_PULL_REQUEST_FILES,
  findHighRiskPaths,
  findSecretPatterns,
  getScanCoverage,
  type ChangedFile,
  type RiskFinding,
  type ScanCoverage,
  type SecretFinding,
} from "./scan.js";

const MAX_ANNOTATIONS = 30;
const MAX_SUMMARY_ROWS = 250;

interface CheckResult {
  name: string;
  succeeded: boolean;
  exitCode: number | null;
  timedOut: boolean;
  timeoutMinutes: number;
}

interface CheckCommand {
  name: "test" | "lint" | "build";
  command: string;
}

interface PullRequestApiFile {
  filename: string;
  status: string;
  patch?: string;
  previous_filename?: string;
}

async function runCheck(
  name: CheckCommand["name"],
  command: string,
  cwd: string,
  timeoutMinutes: number,
): Promise<CheckResult> {
  core.info(`Running configured ${name} check.`);
  const result = await runShellCommand(command, cwd, timeoutMinutes * 60 * 1000);
  const succeeded = result.started && !result.timedOut && result.exitCode === 0;

  if (succeeded) {
    core.info(`Configured ${name} check passed.`);
  } else if (!result.started) {
    core.warning(`The configured ${name} check could not be started.`);
  } else if (result.timedOut) {
    core.warning(`Configured ${name} check exceeded ${timeoutMinutes} minutes and was terminated.`);
  } else {
    core.warning(`Configured ${name} check failed${result.exitCode === null ? "" : ` with exit code ${result.exitCode}`}.`);
  }

  return { name, succeeded, exitCode: result.exitCode, timedOut: result.timedOut, timeoutMinutes };
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

function addFindingAnnotations(
  secretFindings: SecretFinding[],
  riskFindings: RiskFinding[],
  coverage: ScanCoverage,
): void {
  let annotationCount = 0;

  if (!coverage.completeForReturnedFiles && annotationCount < MAX_ANNOTATIONS) {
    core.warning("Sensitive-pattern scan coverage is incomplete. See the step summary for missing patch files or a possible API cap.");
    annotationCount += 1;
  }

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
  coverage: ScanCoverage,
  checkResults: CheckResult[],
): Promise<void> {
  const summary = core.summary;
  const patchAvailableCount = files.length - coverage.missingPatchFiles.length;
  const coverageReasons: string[] = [];
  if (coverage.missingPatchFiles.length > 0) {
    coverageReasons.push(`${coverage.missingPatchFiles.length} returned file(s) had no patch text`);
  }
  if (coverage.fileLimitReached) {
    coverageReasons.push(`the ${MAX_GITHUB_PULL_REQUEST_FILES}-file API response cap may have been reached`);
  }

  const rows: string[][] = [
    ["Check", "Result", "Details"],
    ["Changed files", String(files.length), "Files returned by the GitHub pull request API"],
    [
      "Diff coverage",
      coverage.completeForReturnedFiles ? "No known omissions" : "INCOMPLETE",
      coverageReasons.length > 0
        ? coverageReasons.join("; ")
        : "Every returned file included patch text and the result stayed below the API cap",
    ],
    ["Patch text", `${patchAvailableCount}/${files.length}`, "Returned files with non-empty patch text"],
    ["Potential API truncation", coverage.fileLimitReached ? "Possible" : "Not indicated", "At the cap, additional files may be omitted"],
    ["Sensitive patterns", String(secretFindings.length), "Known patterns found on added diff lines only"],
    ["High-risk paths", String(riskFindings.length), "Changed workflow, dependency, build, ownership, or security configuration"],
  ];

  for (const result of checkResults) {
    let details: string;
    if (result.timedOut) {
      details = `Timed out after ${result.timeoutMinutes} minutes`;
    } else if (result.exitCode === null) {
      details = "Could not start";
    } else {
      details = `Exit code ${result.exitCode}`;
    }

    rows.push([
      `${result.name} command`,
      result.succeeded ? "Passed" : "Failed",
      details,
    ]);
  }

  let detailRowCount = 0;
  for (const filename of coverage.missingPatchFiles) {
    if (detailRowCount >= MAX_SUMMARY_ROWS) {
      break;
    }
    rows.push(["Unscanned file", "Patch text unavailable", filename]);
    detailRowCount += 1;
  }

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
    const pathDescription =
      finding.previousFilename !== undefined && finding.previousFilename !== finding.file
        ? `${finding.previousFilename} → ${finding.file}`
        : finding.affectedPath;
    rows.push(["High-risk path", finding.ruleName, pathDescription]);
    detailRowCount += 1;
  }

  const totalDetails = coverage.missingPatchFiles.length + secretFindings.length + riskFindings.length;
  if (totalDetails > detailRowCount) {
    rows.push(["Additional findings", "Omitted from detail table", "Counts above include every finding"]);
  }

  summary
    .addHeading("PatchProof evidence report", 2)
    .addRaw("<p>PatchProof reports evidence from this pull request. It does not approve, reject, or comment on the pull request.</p>\n")
    .addTable(rows)
    .addHeading("Scan limits", 3)
    .addList([
      "Sensitive-value checks inspect only added lines in patch text returned by GitHub. A complete-for-returned-files status does not prove GitHub returned every diff line; review large and binary changes separately.",
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

  return files.map((file: PullRequestApiFile) => {
    const changedFile: ChangedFile = {
      filename: file.filename,
      status: file.status,
      patch: file.patch,
    };
    if (file.previous_filename !== undefined) {
      changedFile.previousFilename = file.previous_filename;
    }
    return changedFile;
  });
}

async function main(): Promise<void> {
  const pullRequestNumber = getPullRequestNumber();
  const githubToken = core.getInput("github-token", { required: true });
  const failOnSecrets = core.getBooleanInput("fail-on-secrets");
  const failOnRiskyPaths = core.getBooleanInput("fail-on-risky-paths");
  const failOnIncompleteScan = core.getBooleanInput("fail-on-incomplete-scan");
  const timeoutInput = core.getInput("command-timeout-minutes") || String(DEFAULT_COMMAND_TIMEOUT_MINUTES);
  const commandTimeoutMinutes = parseCommandTimeoutMinutes(timeoutInput);
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
  const scanCoverage = getScanCoverage(files);
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
    checkResults.push(await runCheck(checkCommand.name, checkCommand.command, repositoryPath, commandTimeoutMinutes));
  }

  addFindingAnnotations(secretFindings, riskFindings, scanCoverage);
  await writeSummary(files, secretFindings, riskFindings, scanCoverage, checkResults);

  core.setOutput("changed-files", String(files.length));
  core.setOutput("secret-findings", String(secretFindings.length));
  core.setOutput("high-risk-paths", String(riskFindings.length));
  core.setOutput("scan-coverage-complete", String(scanCoverage.completeForReturnedFiles));
  core.setOutput("unscanned-files", String(scanCoverage.missingPatchFiles.length));

  const failedChecks = checkResults.some((result) => !result.succeeded);
  const blockingFindings =
    (failOnSecrets && secretFindings.length > 0) ||
    (failOnRiskyPaths && riskFindings.length > 0) ||
    (failOnIncompleteScan && !scanCoverage.completeForReturnedFiles);

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
    if (failOnIncompleteScan && !scanCoverage.completeForReturnedFiles) {
      reasons.push("sensitive-pattern scan coverage is incomplete");
    }
    core.setFailed(`PatchProof failed because ${reasons.join(" and ")}. See the step summary for details.`);
  }
}

main().catch((error: unknown) => {
  core.setFailed(error instanceof Error ? error.message : "PatchProof failed with an unknown error.");
});
