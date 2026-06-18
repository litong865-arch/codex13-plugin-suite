# Supply Chain Guide

V4 内置标准库静态检查，并生成 SARIF/JUnit。

上线前仍建议在 CI 中运行：

- `npm audit --json`
- `pip-audit`
- `cargo audit`
- Docker image scan
- GitHub dependency review

必须检查：

- lockfile 是否存在。
- install/postinstall/prepare 是否执行网络或 shell。
- GitHub Actions permissions 是否最小权限。
- Dockerfile 是否 root 运行。
- 镜像 tag 是否固定。
- CI secrets 是否通过 secrets store。
