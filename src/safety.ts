const CREDENTIAL_ENVIRONMENT_NAME = /(?:token|secret|password|passwd|credential|private.?key|access.?key|auth)/i;
const ACTION_CONTROL_FILE_ENVIRONMENT_NAMES = new Set([
  "GITHUB_ENV",
  "GITHUB_OUTPUT",
  "GITHUB_PATH",
  "GITHUB_STEP_SUMMARY",
  "GITHUB_STATE",
]);

/** Remove Actions command files, runtime credentials, action inputs, and credential-named variables before running untrusted commands. */
export function sanitizeChildEnvironment(environment: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const safeEnvironment: NodeJS.ProcessEnv = {};

  for (const [name, value] of Object.entries(environment)) {
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
