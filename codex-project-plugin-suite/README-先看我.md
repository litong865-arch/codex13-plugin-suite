# Codex 项目开发插件 13 件套

这是一个给 Codex 使用的本地插件安装包。

解压后，你会看到：

- `plugins/`：13 个插件安装包。
- `install.ps1`：真正执行安装的 PowerShell 脚本。
- `Install-Double-Click.bat`：小白推荐入口，双击它就会调用安装脚本。
- `docs/Codex项目开发插件清单.docx`：插件清单 Word 文档。
- `安装说明-小白版.md`：一步一步安装说明。
- `小白指挥Codex说明.md`：安装后怎么指挥 Codex 使用这些插件。
- `marketplace/marketplace.json`：个人本地 marketplace 示例。

## 最简单安装方式

1. 先把这个压缩包完整解压。
2. 进入解压后的文件夹。
3. 双击 `Install-Double-Click.bat`。
4. 等窗口显示“安装完成”。
5. 完全退出并重启 Codex。
6. 新开一个会话，从已安装插件里选择 `项目总控闸门 / project-master-gate`。

## 安装后测试

新开 Codex 会话，输入：

```text
先不要写代码，请使用项目总控闸门帮我分析这个项目：

我想做一个餐饮商家 AI 评论回复 Agent。

请告诉我应该按什么插件顺序推进，并给出每一步的调用提示词。
```

如果 Codex 能输出“项目总控闸门报告”，说明安装成功。
