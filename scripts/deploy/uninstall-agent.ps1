# uninstall-agent.ps1 — Z-EDR 探针卸载（运维平台/RMM 可直接投递）
#
# 用法（管理员 PowerShell）：
#   .\uninstall-agent.ps1              # 停止并卸载服务，保留数据目录（取证优先）
#   .\uninstall-agent.ps1 -Purge       # 同时删除数据目录（基线/离线队列/本地令牌）
#   .\uninstall-agent.ps1 -RemoveUI    # 同时移除托盘登录自启动
[CmdletBinding()]
param(
  [switch] $Purge,
  [switch] $RemoveUI,
  [string] $Dir = "C:\Program Files\Z-EDR"
)
$ErrorActionPreference = "Stop"

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "需要管理员权限运行"
  exit 2
}

$agent = Join-Path $Dir "bin\zedr-agent.exe"
if (-not (Test-Path $agent)) {
  Write-Warning "未找到 $agent（可能已卸载），仍尝试按服务名卸载"
  $agent = "zedr-agent.exe"
}

if ($Purge) { & $agent -uninstall -purge } else { & $agent -uninstall }
if ($LASTEXITCODE -ne 0) {
  Write-Error "卸载失败（退出码 $LASTEXITCODE）"
  exit $LASTEXITCODE
}
Write-Host "✔ 探针服务已卸载"

if ($RemoveUI) {
  $ui = Join-Path $Dir "bin\zedr-ui.exe"
  if (Test-Path $ui) { & $ui -autostart off | Out-Null }
  Write-Host "✔ 托盘登录自启动已移除"
}

if (-not $Purge) {
  Write-Host "提示: 数据目录（基线/离线队列）已保留；确认无需取证时用 -Purge 一并清除"
}
exit 0
