import { spawn, type ChildProcess } from "node:child_process";
import { sanitizeChildEnvironment } from "./safety.js";

export const DEFAULT_COMMAND_TIMEOUT_MINUTES = 10;
export const MAX_COMMAND_TIMEOUT_MINUTES = 360;
export const PROCESS_TERMINATION_GRACE_MS = 5000;

export interface ShellCommandResult {
  started: boolean;
  exitCode: number | null;
  timedOut: boolean;
}

interface ProcessTreeTermination {
  forceKillTimer: NodeJS.Timeout;
  processGroupMonitor?: NodeJS.Timeout;
  forceKillAttempted: boolean;
}

function processGroupExists(processId: number): boolean {
  try {
    process.kill(-processId, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function clearTerminationTimers(termination: ProcessTreeTermination): void {
  clearTimeout(termination.forceKillTimer);
  if (termination.processGroupMonitor !== undefined) {
    clearInterval(termination.processGroupMonitor);
    termination.processGroupMonitor = undefined;
  }
}

export function parseCommandTimeoutMinutes(input: string): number {
  const timeoutMinutes = Number(input);
  if (
    !Number.isSafeInteger(timeoutMinutes) ||
    timeoutMinutes < 1 ||
    timeoutMinutes > MAX_COMMAND_TIMEOUT_MINUTES
  ) {
    throw new Error(`command-timeout-minutes must be a whole number between 1 and ${MAX_COMMAND_TIMEOUT_MINUTES}.`);
  }

  return timeoutMinutes;
}

function terminateProcessTree(childProcess: ChildProcess, forceKillDelayMs: number): ProcessTreeTermination | undefined {
  const processId = childProcess.pid;
  if (processId === undefined) {
    childProcess.kill();
    return undefined;
  }

  if (process.platform === "win32") {
    let fallbackSent = false;
    const fallbackToDirectKill = (): void => {
      if (!fallbackSent && childProcess.exitCode === null) {
        fallbackSent = true;
        childProcess.kill();
      }
    };

    try {
      const treeTerminator = spawn("taskkill.exe", ["/PID", String(processId), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
      treeTerminator.once("error", fallbackToDirectKill);
      treeTerminator.once("close", (exitCode) => {
        if (exitCode !== 0) {
          fallbackToDirectKill();
        }
      });
    } catch {
      fallbackToDirectKill();
    }

    return undefined;
  }

  try {
    process.kill(-processId, "SIGTERM");
  } catch (error) {
    const errorCode = (error as NodeJS.ErrnoException).code;
    if (errorCode !== "ESRCH") {
      process.stderr.write(`Could not signal the command process group: ${String(error)}\n`);
      childProcess.kill("SIGTERM");
    }
  }

  const termination: ProcessTreeTermination = {
    forceKillTimer: setTimeout(() => {
      termination.forceKillAttempted = true;
      if (!processGroupExists(processId)) {
        clearTerminationTimers(termination);
        return;
      }

      try {
        process.kill(-processId, "SIGKILL");
      } catch (error) {
        const errorCode = (error as NodeJS.ErrnoException).code;
        if (errorCode !== "ESRCH") {
          process.stderr.write(`Could not force-stop the command process group: ${String(error)}\n`);
        }
      }

      if (termination.processGroupMonitor !== undefined) {
        clearInterval(termination.processGroupMonitor);
        termination.processGroupMonitor = undefined;
      }
    }, forceKillDelayMs),
    forceKillAttempted: false,
  };

  return termination;
}

/** Run a workflow-authored shell command with a hard timeout and process-tree cleanup. */
export function runShellCommand(
  command: string,
  cwd: string,
  timeoutMs: number,
  forceKillDelayMs = PROCESS_TERMINATION_GRACE_MS,
): Promise<ShellCommandResult> {
  return new Promise((resolve) => {
    let childProcess: ChildProcess;
    try {
      childProcess = spawn(command, [], {
        cwd,
        env: sanitizeChildEnvironment(process.env),
        shell: true,
        stdio: "inherit",
        windowsHide: true,
        detached: process.platform !== "win32",
      });
    } catch {
      resolve({ started: false, exitCode: null, timedOut: false });
      return;
    }

    let spawnFailed = false;
    let timedOut = false;
    let timeoutTimer: NodeJS.Timeout | undefined;
    let termination: ProcessTreeTermination | undefined;
    childProcess.once("error", () => {
      spawnFailed = true;
    });

    childProcess.once("close", (exitCode) => {
      if (timeoutTimer !== undefined) {
        clearTimeout(timeoutTimer);
      }
      const activeTermination = termination;
      if (activeTermination !== undefined) {
        const processId = childProcess.pid;
        const processGroupHasExited = processId === undefined || !processGroupExists(processId);
        if (processGroupHasExited || activeTermination.forceKillAttempted) {
          clearTerminationTimers(activeTermination);
        } else {
          activeTermination.processGroupMonitor = setInterval(() => {
            if (processId === undefined || !processGroupExists(processId)) {
              clearTerminationTimers(activeTermination);
            }
          }, 25);
        }
      }

      resolve({ started: !spawnFailed, exitCode, timedOut });
    });

    timeoutTimer = setTimeout(() => {
      timedOut = true;
      termination = terminateProcessTree(childProcess, forceKillDelayMs);
    }, timeoutMs);
  });
}
