@echo off
chcp 65001 >nul
title Codex 项目开发插件 13 件套安装器
echo.
echo 正在安装 Codex 项目开发插件 13 件套...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
echo.
echo 如果上面显示“安装完成”，请关闭本窗口，然后重启 Codex。
echo.
pause
