export const MAX_GITHUB_PULL_REQUEST_FILES = 3000;

const PRIVATE_KEY_PATTERN = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/i;

const SECRET_PATTERNS = [
  { name: "Private key block", pattern: PRIVATE_KEY_PATTERN },
  { name: "AWS access key ID", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
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

export interface ChangedFile {
  filename: string;
  status: string;
  patch?: string;
  previousFilename?: string;
}

export interface SecretFinding {
  file: string;
  line: number;
  patternName: string;
}

export interface RiskFinding {
  file: string;
  affectedPath: string;
  previousFilename?: string;
  ruleName: string;
}

export interface AddedLine {
  lineNumber: number;
  text: string;
}

export interface ScanCoverage {
  completeForReturnedFiles: boolean;
  missingPatchFiles: string[];
  fileLimitReached: boolean;
}

/** Extract added lines from unified diff text without confusing added `++` lines for file headers. */
export function getAddedLines(patch: string): AddedLine[] {
  const addedLines: AddedLine[] = [];
  let newLineNumber = 0;
  let insideHunk = false;

  for (const line of patch.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      insideHunk = false;
      continue;
    }

    const hunkMatch = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunkMatch !== null) {
      insideHunk = true;
      newLineNumber = Number(hunkMatch[1]);
      continue;
    }

    if (!insideHunk) {
      continue;
    }

    if (line.startsWith("\\")) {
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

export function findSecretPatterns(files: ChangedFile[]): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const file of files) {
    if (typeof file.patch !== "string" || file.patch.length === 0) {
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

export function findHighRiskPaths(files: ChangedFile[]): RiskFinding[] {
  const findings: RiskFinding[] = [];

  for (const file of files) {
    const changedPaths = [file.filename];
    if (file.previousFilename !== undefined && file.previousFilename !== file.filename) {
      changedPaths.push(file.previousFilename);
    }

    for (const changedPath of changedPaths) {
      const matchingRule = HIGH_RISK_PATH_RULES.find((rule) => rule.pattern.test(changedPath));
      if (matchingRule !== undefined) {
        findings.push({
          file: file.filename,
          affectedPath: changedPath,
          previousFilename: file.previousFilename,
          ruleName: matchingRule.name,
        });
        break;
      }
    }
  }

  return findings;
}

export function getScanCoverage(files: ChangedFile[]): ScanCoverage {
  const missingPatchFiles = files
    .filter((file) => typeof file.patch !== "string" || file.patch.length === 0)
    .map((file) => file.filename);
  const fileLimitReached = files.length >= MAX_GITHUB_PULL_REQUEST_FILES;

  return {
    completeForReturnedFiles: missingPatchFiles.length === 0 && !fileLimitReached,
    missingPatchFiles,
    fileLimitReached,
  };
}
