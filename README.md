# PatchProof

PatchProof is a small GitHub Action that puts review evidence in the pull request workflow run. It reads the changed-file list and available diff patches, checks added lines for several recognizable credential patterns, flags changes to security-sensitive repository paths, and can run the test, lint, and build commands you configure.

PatchProof does not approve pull requests, post comments, change labels, or send source code to an external model.

## What it checks

- Runs optional test, lint, and build shell commands in the checked-out workspace, in that order.
- Scans added diff lines returned by GitHub for private-key headers, common AWS, GitHub, Slack, and Google credential formats, and credential-like assignments.
- Warns when changes touch workflow/action files, dependency manifests, build/deployment configuration, ownership files, or security configuration.
- Writes counts, check results, findings, and scan limits to `GITHUB_STEP_SUMMARY`; emits file annotations without printing detected credential values.

## Quick start

Add a workflow such as `.github/workflows/patchproof.yml`:

```yaml
name: PatchProof

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read

jobs:
  patchproof:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Run PatchProof
        uses: Andy123211/patchproof@v1
        with:
          github-token: ${{ github.token }}
          test-command: npm test --if-present
          lint-command: npm run lint --if-present
          build-command: npm run build --if-present
```

For stronger supply-chain protection, pin the action reference to a verified full commit SHA. The checkout step is only needed when you configure commands that require repository files.

The action supports these inputs:

| Input | Required | Default | Behavior |
| --- | --- | --- | --- |
| `github-token` | Yes | — | Read-only token used to list pull request files. Grant `pull-requests: read`. |
| `test-command` | No | Empty | Shell command for the test check. |
| `lint-command` | No | Empty | Shell command for the lint check. |
| `build-command` | No | Empty | Shell command for the build check. |
| `fail-on-secrets` | No | `true` | Fail when a known sensitive-value pattern is found. |
| `fail-on-risky-paths` | No | `false` | Make high-risk path changes fail instead of warn. |

Configured commands run sequentially. A non-zero exit status fails the action. If a command is omitted, it is skipped. Risky paths are warnings by default; set `fail-on-risky-paths: true` to make them blocking.

## Security notes

- Run PatchProof on `pull_request` with a read-only `GITHUB_TOKEN`. Do not use `pull_request_target`: test, lint, and build commands execute code in the checked-out pull request and can be controlled by its author.
- Run untrusted pull request commands only on a clean, ephemeral GitHub-hosted runner. Avoid persistent or self-hosted runners, where a pull request command could affect later jobs or access runner-local state.
- Do not expose repository secrets to a job that runs commands from untrusted pull requests. PatchProof removes common credential-named environment variables and GitHub Actions runtime credentials from its child command environment, but it cannot identify secrets stored under arbitrary variable names or prevent a command from obtaining credentials through other means.
- The configured commands do not inherit GitHub Actions control-file paths (`GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_PATH`, `GITHUB_STEP_SUMMARY`, or `GITHUB_STATE`), `ACTIONS_*` runtime variables, or `INPUT_*` action inputs.
- Keep job permissions minimal. PatchProof only needs `pull-requests: read`; `contents: read` is generally needed by `actions/checkout`.
- Shell commands are intentionally supplied by the workflow author. Treat command inputs as executable code and review workflow changes.
- PatchProof does not make a security decision for you. Its path rules are review prompts, and a detected pattern may be a false positive.

## Scan coverage and limits

The secret-pattern scan examines only added lines in unified diff text provided by the GitHub pull request files API. GitHub may omit patch text for binary, large, or otherwise unsupported diffs; this is shown in the step summary. GitHub also limits the number of files returned by that endpoint. Patterns cannot recognize every credential format, and a clean report is not proof that a change is safe. Use a dedicated secret scanner for broader coverage.

Sensitive values are never included in PatchProof's own annotation or summary text. GitHub annotations are capped to keep large pull requests usable; counts and detail rows remain in the step summary.

## Development

Requires Node.js 24 or newer.

```sh
npm install
npm run typecheck
npm run build
```

`npm run build` type-checks the TypeScript source and bundles `src/index.ts` into `dist/index.js`, which is committed so GitHub can execute the action without installing dependencies.

## License

MIT. See [LICENSE](LICENSE).

---

## 简体中文

PatchProof 是一个 GitHub Action：它读取 PR 文件列表和 GitHub 提供的 diff，扫描新增行中的常见凭据特征，提示高风险仓库路径变更，并按配置运行测试、Lint 和构建命令。结果会写入 Actions 步骤摘要，并为具体文件生成提醒。

请只在干净、临时的 GitHub 托管 Runner 上，以 `pull_request` 事件和只读 `GITHUB_TOKEN` 运行不可信 PR 命令。不要使用 `pull_request_target`、持久化或自托管 Runner，也不要暴露仓库密钥。命令由工作流作者配置，会在检出的 PR 代码上执行；子命令不会继承 Actions 控制文件路径或 `ACTIONS_*` 运行时变量。

扫描仅覆盖 GitHub API 返回的 diff 文本；二进制、大文件或缺少 patch 的改动不会被完整扫描。规则可能误报，也可能漏报，不能替代专用密钥扫描器和人工审查。
