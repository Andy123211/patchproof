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
    timeout-minutes: 35
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Run PatchProof
        uses: Andy123211/patchproof@v1
        with:
          github-token: ${{ github.token }}
          command-timeout-minutes: 10
          fail-on-incomplete-scan: true
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
| `command-timeout-minutes` | No | `10` | Per-command timeout, from 1 to 360 whole minutes. Timed-out process trees are terminated. |
| `fail-on-secrets` | No | `true` | Fail when a known sensitive-value pattern is found. |
| `fail-on-risky-paths` | No | `false` | Make high-risk path changes fail instead of warn. |
| `fail-on-incomplete-scan` | No | `false` | Fail when returned files lack patch text or the GitHub file-list cap may have been reached. |

Configured commands run sequentially. A non-zero exit status or command timeout fails the action. If a command is omitted, it is skipped. Risky paths and incomplete scan coverage are warnings by default; set the corresponding `fail-on-*` input to make them blocking. The workflow job should also have an overall `timeout-minutes` limit.

## Security notes

- Run PatchProof on `pull_request` with a read-only `GITHUB_TOKEN`. Do not use `pull_request_target`: test, lint, and build commands execute code in the checked-out pull request and can be controlled by its author.
- Run untrusted pull request commands only on a clean, ephemeral GitHub-hosted runner. Avoid persistent or self-hosted runners, where a pull request command could affect later jobs or access runner-local state.
- Do not expose repository secrets to a job that runs commands from untrusted pull requests. PatchProof removes common credential-named environment variables and GitHub Actions runtime credentials from its child command environment, but it cannot identify secrets stored under arbitrary variable names or prevent a command from obtaining credentials through other means.
- The configured commands do not inherit GitHub Actions control-file paths (`GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_PATH`, `GITHUB_STEP_SUMMARY`, or `GITHUB_STATE`), `ACTIONS_*` runtime variables, or `INPUT_*` action inputs.
- Keep job permissions minimal. PatchProof only needs `pull-requests: read`; `contents: read` is generally needed by `actions/checkout`.
- Shell commands are intentionally supplied by the workflow author. Treat command inputs as executable code and review workflow changes.
- PatchProof does not make a security decision for you. Its path rules are review prompts, and a detected pattern may be a false positive.

## Scan coverage and limits

The secret-pattern scan examines only added lines in non-empty unified diff text provided by the GitHub pull request files API. The summary lists files without patch text and marks coverage incomplete; it also warns when the response reaches GitHub's 3,000-file cap, where additional files may be omitted. The `scan-coverage-complete` output means only that every returned file had patch text and the cap was not reached; it cannot prove GitHub returned every diff line. Patterns cannot recognize every credential format, and a clean report is not proof that a change is safe. Use a dedicated secret scanner for broader coverage.

Sensitive values are never included in PatchProof's own annotation or summary text. GitHub annotations are capped to keep large pull requests usable; counts and detail rows remain in the step summary.

## Development

Requires Node.js 24 or newer.

```sh
npm install
npm run test
npm run typecheck
npm run build
```

`npm run test` runs the built-in Node.js regression tests. GitHub Actions CI runs the tests, type check, and build on Node.js 24, then verifies that the committed bundle is up to date. `npm run build` type-checks the TypeScript source and bundles `src/index.ts` into `dist/index.js`, which is committed so GitHub can execute the action without installing dependencies.

## License

MIT. See [LICENSE](LICENSE).

---

## 简体中文

PatchProof 是一个 GitHub Action：它读取 PR 文件列表和 GitHub 提供的 diff，扫描新增行中的常见凭据特征，提示高风险仓库路径变更，并按配置运行测试、Lint 和构建命令。结果会写入 Actions 步骤摘要，并为具体文件生成提醒。

请只在干净、临时的 GitHub 托管 Runner 上，以 `pull_request` 事件和只读 `GITHUB_TOKEN` 运行不可信 PR 命令。不要使用 `pull_request_target`、持久化或自托管 Runner，也不要暴露仓库密钥。命令由工作流作者配置，会在检出的 PR 代码上执行；子命令不会继承 Actions 控制文件路径或 `ACTIONS_*` 运行时变量。

扫描只检查 GitHub API 返回的非空 diff 新增行。摘要会列出缺少 patch 文本的文件，并在达到 3,000 文件 API 上限时标记覆盖不完整；`scan-coverage-complete` 只表示返回的文件都有 patch 且未触及该上限，不保证 API 返回了每一行 diff。命令默认每条 10 分钟超时。规则可能误报或漏报，不能替代专用密钥扫描器和人工审查。
