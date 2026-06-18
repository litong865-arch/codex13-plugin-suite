param(
  [switch]$NoCache
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

$PluginIds = @(
  "project-master-gate",
  "decision-stress-test-gate",
  "product-feasibility-gate",
  "security-release-review",
  "spec-builder",
  "api-platform-gate",
  "ai-cost-estimator",
  "code-drift-inspector",
  "codex-acceptance-reviewer",
  "release-guardian",
  "beginner-runbook-builder",
  "user-interview-generator",
  "competitor-analyzer"
)

function Write-Section($Text) {
  Write-Host ""
  Write-Host "==== $Text ====" -ForegroundColor Cyan
}

function Ensure-Directory($Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
  }
}

function Assert-ChildPath($Child, $Parent, $Message) {
  $resolvedChild = [System.IO.Path]::GetFullPath($Child)
  $resolvedParent = [System.IO.Path]::GetFullPath($Parent)
  if (-not $resolvedChild.StartsWith($resolvedParent, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw $Message
  }
}

$PackageRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourcePluginsRoot = Join-Path $PackageRoot "plugins"
$HomeDir = [Environment]::GetFolderPath("UserProfile")
$CodexDir = Join-Path $HomeDir ".codex"
$TargetPluginsRoot = Join-Path $CodexDir "plugins"
$CacheRoot = Join-Path $CodexDir "plugins\cache\personal"
$AgentsPluginsDir = Join-Path $HomeDir ".agents\plugins"
$MarketplacePath = Join-Path $AgentsPluginsDir "marketplace.json"
$ConfigPath = Join-Path $CodexDir "config.toml"
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupRoot = Join-Path $CodexDir "plugins\backups\project-plugin-suite-$Timestamp"

Write-Section "检查安装包"
if (-not (Test-Path -LiteralPath $SourcePluginsRoot)) {
  throw "安装包缺少 plugins 目录：$SourcePluginsRoot"
}

foreach ($id in $PluginIds) {
  $src = Join-Path $SourcePluginsRoot $id
  $manifest = Join-Path $src ".codex-plugin\plugin.json"
  if (-not (Test-Path -LiteralPath $manifest)) {
    throw "插件缺少 plugin.json：$id"
  }
  Write-Host "OK: $id"
}

Write-Section "复制插件到当前用户 Codex 插件目录"
Ensure-Directory $TargetPluginsRoot
foreach ($id in $PluginIds) {
  $src = Join-Path $SourcePluginsRoot $id
  $dest = Join-Path $TargetPluginsRoot $id
  Assert-ChildPath $dest $TargetPluginsRoot "目标插件路径异常：$dest"

  if (Test-Path -LiteralPath $dest) {
    Ensure-Directory $BackupRoot
    $backupDest = Join-Path $BackupRoot $id
    Copy-Item -LiteralPath $dest -Destination $backupDest -Recurse -Force
    Remove-Item -LiteralPath $dest -Recurse -Force
    Write-Host "已备份旧版本：$backupDest"
  }

  Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force
  Write-Host "已安装插件源目录：$id"
}

Write-Section "更新个人 marketplace"
Ensure-Directory $AgentsPluginsDir
$marketplace = $null
if (Test-Path -LiteralPath $MarketplacePath) {
  try {
    $marketplace = Get-Content -LiteralPath $MarketplacePath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    $brokenBackup = "$MarketplacePath.broken-$Timestamp"
    Copy-Item -LiteralPath $MarketplacePath -Destination $brokenBackup -Force
    Write-Host "原 marketplace 无法解析，已备份为：$brokenBackup"
  }
}

if ($null -eq $marketplace) {
  $marketplace = [pscustomobject]@{
    name = "personal"
    interface = [pscustomobject]@{ displayName = "Personal" }
    plugins = @()
  }
}

if (-not $marketplace.PSObject.Properties.Name.Contains("name") -or [string]::IsNullOrWhiteSpace($marketplace.name)) {
  $marketplace | Add-Member -NotePropertyName name -NotePropertyValue "personal" -Force
}
if (-not $marketplace.PSObject.Properties.Name.Contains("interface") -or $null -eq $marketplace.interface) {
  $marketplace | Add-Member -NotePropertyName interface -NotePropertyValue ([pscustomobject]@{ displayName = "Personal" }) -Force
}
if (-not $marketplace.interface.PSObject.Properties.Name.Contains("displayName") -or [string]::IsNullOrWhiteSpace($marketplace.interface.displayName)) {
  $marketplace.interface | Add-Member -NotePropertyName displayName -NotePropertyValue "Personal" -Force
}
if (-not $marketplace.PSObject.Properties.Name.Contains("plugins") -or $null -eq $marketplace.plugins) {
  $marketplace | Add-Member -NotePropertyName plugins -NotePropertyValue @() -Force
}

$plugins = @($marketplace.plugins)
foreach ($id in $PluginIds) {
  $entry = [pscustomobject]@{
    name = $id
    source = [pscustomobject]@{
      source = "local"
      path = "./.codex/plugins/$id"
    }
    policy = [pscustomobject]@{
      installation = "AVAILABLE"
      authentication = "ON_INSTALL"
    }
    category = "Productivity"
  }

  $existing = @($plugins | Where-Object { $_.name -eq $id })
  if ($existing.Count -gt 0) {
    foreach ($old in $existing) {
      $old.source = $entry.source
      $old.policy = $entry.policy
      $old.category = $entry.category
    }
    Write-Host "已更新 marketplace 条目：$id"
  } else {
    $plugins += $entry
    Write-Host "已添加 marketplace 条目：$id"
  }
}

$marketplace.plugins = $plugins
$marketplace | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $MarketplacePath -Encoding UTF8

Write-Section "写入 Codex 已启用插件配置"
Ensure-Directory $CodexDir
if (Test-Path -LiteralPath $ConfigPath) {
  $config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
} else {
  $config = ""
}

if ($config -notmatch '(?m)^\[marketplaces\.personal\]') {
  $homeToml = $HomeDir.Replace("\", "\\")
  $config = $config.TrimEnd() + "`r`n`r`n[marketplaces.personal]`r`nsource_type = `"local`"`r`nsource = '$homeToml'`r`n"
  Write-Host "已添加 personal marketplace 配置"
}

foreach ($id in $PluginIds) {
  $header = "[plugins.`"$id@personal`"]"
  $escapedHeader = [regex]::Escape($header)
  $sectionPattern = "$escapedHeader`r?`n([\s\S]*?)(?=`r?`n\[|$)"

  if ([regex]::IsMatch($config, $sectionPattern)) {
    $config = [regex]::Replace($config, $sectionPattern, {
      param($match)
      $body = $match.Groups[1].Value
      if ($body -match '(?m)^enabled\s*=') {
        $body = [regex]::Replace($body, '(?m)^enabled\s*=.*$', 'enabled = true')
      } else {
        $body = "enabled = true`r`n" + $body.TrimStart()
      }
      return "$header`r`n$($body.TrimEnd())`r`n"
    })
    Write-Host "已启用：$id@personal"
  } else {
    $config = $config.TrimEnd() + "`r`n`r`n$header`r`nenabled = true`r`n"
    Write-Host "已添加启用项：$id@personal"
  }
}

Set-Content -LiteralPath $ConfigPath -Encoding UTF8 -Value $config

if (-not $NoCache) {
  Write-Section "同步 installed cache"
  Ensure-Directory $CacheRoot
  foreach ($id in $PluginIds) {
    $installedSrc = Join-Path $TargetPluginsRoot $id
    $manifestPath = Join-Path $installedSrc ".codex-plugin\plugin.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = $manifest.version
    if ([string]::IsNullOrWhiteSpace($version)) {
      throw "插件版本号为空：$id"
    }

    $cacheDest = Join-Path $CacheRoot "$id\$version"
    Assert-ChildPath $cacheDest $CacheRoot "缓存目标路径异常：$cacheDest"
    if (Test-Path -LiteralPath $cacheDest) {
      Remove-Item -LiteralPath $cacheDest -Recurse -Force
    }
    Ensure-Directory (Split-Path -Parent $cacheDest)
    Copy-Item -LiteralPath $installedSrc -Destination $cacheDest -Recurse -Force
    Write-Host "已同步缓存：$id $version"
  }
}

Write-Section "安装完成"
Write-Host "已安装并启用 13 个插件。"
Write-Host "请完全退出并重启 Codex。"
Write-Host "重启后打开新会话，在已安装插件里选择：项目总控闸门 / project-master-gate。"
Write-Host ""
Write-Host "推荐测试提示词："
Write-Host "先不要写代码，请使用项目总控闸门帮我分析这个项目：我想做一个餐饮商家 AI 评论回复 Agent。请告诉我应该按什么插件顺序推进。"
