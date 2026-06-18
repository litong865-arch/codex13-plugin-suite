# Git 工作流检查清单

Codex 开始写代码前，必须检查：

- 是否 git init
- 是否创建 .gitignore
- 是否忽略 .env / .env.local
- 是否完成第一次 commit
- 是否每个关键节点 commit
- 是否有回滚方式
- 是否在大规模修改前创建检查点
- 是否能查看 diff
- 是否能撤销失败改动

建议流程：

1. git init
2. 创建 .gitignore
3. 提交初始项目结构
4. 每完成一个小目标 commit
5. Codex 大改前先检查 git status
6. 出错时回滚到上一个可用提交
