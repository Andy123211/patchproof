import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { parseCommandTimeoutMinutes, runShellCommand } from "../.test-build/commands.js";
import { sanitizeChildEnvironment } from "../.test-build/safety.js";
import {
  findHighRiskPaths,
  findSecretPatterns,
  getAddedLines,
  getScanCoverage,
  MAX_GITHUB_PULL_REQUEST_FILES,
} from "../.test-build/scan.js";

function quoteShellArgument(value) {
  if (process.platform === "win32") {
    return `"${value}"`;
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}

test("diff parser scans added content that starts with two plus signs", () => {
  const sampleAwsKey = "AKIA" + "1234567890ABCDEF";
  const patch = [
    "diff --git a/example.txt b/example.txt",
    "index 0000000..1111111 100644",
    "--- a/example.txt",
    "+++ b/example.txt",
    "@@ -1,2 +1,3 @@",
    " retained line",
    "-removed line",
    `+ +${sampleAwsKey}`,
  ].join("\n");

  assert.deepEqual(getAddedLines(patch), [{ lineNumber: 2, text: ` +${sampleAwsKey}` }]);
  assert.deepEqual(
    findSecretPatterns([{ filename: "example.txt", status: "modified", patch }]),
    [{ file: "example.txt", line: 2, patternName: "AWS access key ID" }],
  );
});

test("diff parser treats an added source line beginning with ++ as content, not a header", () => {
  const sampleAwsKey = "AKIA" + "1234567890ABCDEF";
  const patch = ["@@ -0,0 +1 @@", `+++${sampleAwsKey}`].join("\n");

  assert.deepEqual(getAddedLines(patch), [{ lineNumber: 1, text: `++${sampleAwsKey}` }]);
});

test("a rename out of a high-risk directory retains the previous path for review", () => {
  const findings = findHighRiskPaths([
    {
      filename: "docs/old-workflow.txt",
      previousFilename: ".github/workflows/release.yml",
      status: "renamed",
    },
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].affectedPath, ".github/workflows/release.yml");
});

test("missing patch text and the API file cap mark scan coverage incomplete", () => {
  const missingPatch = getScanCoverage([{ filename: "assets/archive.bin", status: "modified" }]);
  assert.equal(missingPatch.completeForReturnedFiles, false);
  assert.deepEqual(missingPatch.missingPatchFiles, ["assets/archive.bin"]);

  const atApiCap = Array.from({ length: MAX_GITHUB_PULL_REQUEST_FILES }, (_value, index) => ({
    filename: `file-${index}.txt`,
    status: "modified",
    patch: "@@ -0,0 +0,0 @@",
  }));
  const cappedCoverage = getScanCoverage(atApiCap);
  assert.equal(cappedCoverage.fileLimitReached, true);
  assert.equal(cappedCoverage.completeForReturnedFiles, false);
});

test("child environment omits Actions control files and credentials but keeps ordinary build variables", () => {
  const safeEnvironment = sanitizeChildEnvironment({
    PATH: "tools",
    CI: "true",
    GITHUB_WORKSPACE: "workspace",
    GITHUB_ENV: "runner-env-file",
    GITHUB_OUTPUT: "runner-output-file",
    GITHUB_PATH: "runner-path-file",
    GITHUB_STEP_SUMMARY: "runner-summary-file",
    GITHUB_STATE: "runner-state-file",
    ACTIONS_RUNTIME_TOKEN: "runtime-token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-token",
    ACTIONS_ID_TOKEN_REQUEST_URL: "oidc-url",
    INPUT_GITHUB_TOKEN: "action-token",
    GITHUB_TOKEN: "job-token",
    GH_TOKEN: "cli-token",
    NODE_AUTH_TOKEN: "npm-token",
    AWS_ACCESS_KEY_ID: "cloud-key-id",
  });

  assert.deepEqual(safeEnvironment, { PATH: "tools", CI: "true", GITHUB_WORKSPACE: "workspace" });
});

test("command timeout input accepts only whole minutes from 1 through 360", () => {
  assert.equal(parseCommandTimeoutMinutes("10"), 10);
  for (const input of ["", "0", "1.5", "NaN", "361"]) {
    assert.throws(() => parseCommandTimeoutMinutes(input));
  }
});

test("a timed-out command terminates its process tree", { timeout: 10000 }, async () => {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), "patchproof-timeout-"));
  const parentScript = join(temporaryDirectory, "parent.mjs");
  const childScript = join(temporaryDirectory, "delayed-marker.mjs");
  const markerPath = join(temporaryDirectory, "survived.txt");

  try {
    await writeFile(
      parentScript,
      [
        'import { spawn } from "node:child_process";',
        'spawn(process.execPath, [process.argv[2], process.argv[3]], { stdio: "ignore" });',
        "setInterval(() => {}, 1000);",
      ].join("\n"),
    );
    await writeFile(
      childScript,
      [
        'import { writeFile } from "node:fs/promises";',
        'process.on("SIGTERM", () => {});',
        'setTimeout(() => { void writeFile(process.argv[2], "survived"); }, 1500);',
      ].join("\n"),
    );

    const command = [process.execPath, parentScript, childScript, markerPath].map(quoteShellArgument).join(" ");
    const result = await runShellCommand(command, temporaryDirectory, 150, 50);
    await new Promise((resolve) => setTimeout(resolve, 1800));

    assert.equal(result.started, true);
    assert.equal(result.timedOut, true);
    await assert.rejects(readFile(markerPath));
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});

test("a normally exiting SIGTERM process group clears its pending force-kill timer", {
  skip: process.platform === "win32",
  timeout: 10000,
}, async () => {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), "patchproof-sigterm-"));
  const gracefulScript = join(temporaryDirectory, "graceful.mjs");
  const runnerScript = join(temporaryDirectory, "runner.mjs");

  try {
    await writeFile(
      gracefulScript,
      [
        'process.once("SIGTERM", () => setTimeout(() => process.exit(0), 100));',
        "setInterval(() => {}, 1000);",
      ].join("\n"),
    );

    const command = [process.execPath, gracefulScript].map(quoteShellArgument).join(" ");
    const commandsModuleUrl = new URL("../.test-build/commands.js", import.meta.url).href;
    await writeFile(
      runnerScript,
      [
        `import { runShellCommand } from ${JSON.stringify(commandsModuleUrl)};`,
        `const result = await runShellCommand(${JSON.stringify(command)}, ${JSON.stringify(temporaryDirectory)}, 150, 5000);`,
        "console.log(JSON.stringify(result));",
      ].join("\n"),
    );

    const startedAt = Date.now();
    const runnerResult = spawnSync(process.execPath, [runnerScript], {
      encoding: "utf8",
      timeout: 2000,
      windowsHide: true,
    });

    assert.equal(runnerResult.error, undefined, "runner should exit without waiting for the force-kill delay");
    assert.equal(runnerResult.status, 0, runnerResult.stderr);
    assert.equal(JSON.parse(runnerResult.stdout.trim()).timedOut, true);
    assert.ok(Date.now() - startedAt < 2000);
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});
