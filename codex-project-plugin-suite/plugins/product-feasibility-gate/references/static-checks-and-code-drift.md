# 静态检查与 Code Drift

Code Drift 指代码在 AI 多次修改后逐渐漂移：

- 命名不统一
- 目录边界被破坏
- 抽象越来越乱
- mock 和真实逻辑混在一起
- UI 组件越来越大
- 一个文件承担太多职责
- 改一个功能影响多个无关模块

建议检查：

- npm run lint
- npm run typecheck
- npm test
- pytest
- ruff
- mypy
- eslint
- tsc
- 自定义 scripts/check-project-structure.js
- 自定义 scripts/check-project-structure.py

必须检查：

- 页面层是否越界
- API Key 是否暴露
- .env 是否被提交
- mock 是否被标记
- 是否有无验收标准的功能
- 是否有超大文件
- 是否有重复代码
- 是否有废弃文件
