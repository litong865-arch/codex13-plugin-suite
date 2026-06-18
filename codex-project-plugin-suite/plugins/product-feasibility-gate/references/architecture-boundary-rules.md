# 架构边界规则

默认分层：

- UI / pages / components：只负责展示和交互
- services / api：只负责 API 调用
- domain / core：只负责业务规则
- mocks：只负责 mock 数据
- config：只负责配置
- utils：只放通用工具
- scripts：只放自动化脚本

禁止：

- 页面层直接访问数据库
- 页面层硬编码 mock 数据
- 业务逻辑散落在 UI 组件里
- API 调用到处写
- mock 和真实 API 混在一起
- API Key 出现在前端代码
- 一个文件承担太多职责
- 跨层乱调用

原则：

允许局部自由，但必须守住全局边界。
