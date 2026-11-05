# install-agent.ps1 — Z-EDR 探针一键安装（运维平台/RMM 可直接投递）
#
# 用法（管理员 PowerShell）：
#   .\install-agent.ps1 -Url http://10.0.0.2:8080 -Token <注册令牌>
#   .\install-agent.ps1 -Url http://10.0.0.2:8080 -Token <令牌> -Tags office,finance -WithUI
#
# 参数：
#   -Url    总控服务端地址（目标机器可达；必填）
#   -Token  注册预共享令牌（管理台「主机终端 → 接入新主机」获取；必填）
#   -Tags   逗号分隔主机标签（可选）
#   -WithUI 同时安装桌面托盘自启动（可选）
#   -Dir    安装目录（默认 C:\Program Files\Z-EDR）
#
# 退出码：0 成功且探针已上线；2 权限不足；4 参数缺失；其他 = 安装失败。
# 幂等：重复执行等于重装（配置以最后一次为准）。
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string] $Url,
  [Parameter(Mandatory = $true)] [string] $Token,
  [string] $Tags = "",
  [switch] $WithUI,
  [string] $Dir = "C:\Program Files\Z-EDR"
)
$ErrorActionPreference = "Stop"

function Fail([int] $Code, [string] $Msg) {
  Write-Error $Msg -ErrorAction Continue
  exit $Code
}

# ---- 前置检查 ----
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail 2 "需要管理员权限运行（服务安装与写 Program Files 都要求提权）"
}
if (-not $Url -or -not $Token) { Fail 4 "-Url 与 -Token 均为必填" }

$src = $PSScriptRoot
if (-not (Test-Path (Join-Path $src "zedr-agent.exe"))) {
  Fail 4 "未找到 zedr-agent.exe：请把本脚本与部署包内的 exe 放在同一目录（从管理台下载的 zip 解压即可）"
}

# ---- 服务端连通性预检（失败不阻断：现场可能先装后通网络）----
try {
  $null = Invoke-WebRequest -Uri "$Url/health" -UseBasicParsing -TimeoutSec 5
  Write-Host "[1/5] 服务端可达: $Url"
} catch {
  Write-Warning "[1/5] 服务端 $Url 暂不可达（继续安装，探针会自动重连；若一直离线请检查地址/防火墙）"
}

# ---- 重装路径：先停卸旧服务与托盘，再拷文件（运行中的进程会锁住 exe）----
$svc = Get-Service -Name ZEDRAgent -ErrorAction SilentlyContinue
if ($svc) {
  Write-Host "[1.5/5] 检测到已有探针服务，先停止并卸载（幂等重装）"
  sc.exe stop ZEDRAgent | Out-Null
  # 探针优雅停机含上报队列 flush（最长 8s），必须等进程真正退出再拷文件
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline -and (Get-Process -Name "zedr-agent" -ErrorAction SilentlyContinue)) {
    Start-Sleep -Milliseconds 500
  }
  if (Get-Process -Name "zedr-agent" -ErrorAction SilentlyContinue) {
    Stop-Process -Name "zedr-agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
  }
  sc.exe delete ZEDRAgent | Out-Null
  Start-Sleep -Milliseconds 500
}
if ($WithUI) {
  # 旧托盘进程同样会锁 zedr-ui.exe；登录自启随后会重新拉起
  Stop-Process -Name "zedr-ui" -Force -ErrorAction SilentlyContinue
}

# ---- 拷贝文件 ----
$binDir = Join-Path $Dir "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Copy-Item (Join-Path $src "zedr-agent.exe") $binDir -Force
if ($WithUI -and (Test-Path (Join-Path $src "zedr-ui.exe"))) {
  Copy-Item (Join-Path $src "zedr-ui.exe") $binDir -Force
}
Write-Host "[2/5] 程序文件就位: $binDir"

# ---- 安装服务（配置由 -url/-token 落盘到 exe 同目录 .env）----
Write-Host "[3/5] 安装探针服务..."
$agent = Join-Path $binDir "zedr-agent.exe"
# 注意：不用 $args——那是 PowerShell 自动变量，覆盖它是著名的坑。
$agentArgs = @("-install", "-url", $Url, "-token", $Token)
if ($Tags) { $agentArgs += @("-tags", $Tags) }
& $agent @agentArgs
if ($LASTEXITCODE -ne 0) { Fail $LASTEXITCODE "zedr-agent -install 失败（退出码 $LASTEXITCODE）" }

# ---- 托盘自启动（可选，免管理员 HKCU 写入）----
if ($WithUI) {
  $ui = Join-Path $binDir "zedr-ui.exe"
  if (Test-Path $ui) {
    & $ui -autostart on
    Write-Host "[4/5] 桌面托盘已设为登录自启动（下次登录自动运行；双击 zedr-ui.exe 可立即打开）"
  } else {
    Write-Warning "[4/5] 部署包内无 zedr-ui.exe，跳过托盘安装"
  }
} else {
  Write-Host "[4/5] 跳过桌面托盘（未指定 -WithUI）"
}

# ---- 验证：探针本地状态（JSON）----
# enroll（含首次心跳）需要数秒到半分钟，轮询而不是单次检查——运维平台
# 依赖退出码判断装机结果，误报失败比多等几秒代价大。
Write-Host "[5/5] 验证探针接入（最多等 40 秒）..."
$eap = $ErrorActionPreference
$ErrorActionPreference = "Continue"   # PS5.1 下原生命令 stderr + Stop 会抛 NativeCommandError
$online = $false
$statusJson = $null
foreach ($i in 1..20) {
  Start-Sleep -Seconds 2
  $statusJson = (& $agent -status -json 2>$null) -join "" | ConvertFrom-Json
  if ($statusJson -and $statusJson.online) { $online = $true; break }
}
$ErrorActionPreference = $eap
if ($online) {
  Write-Host ""
  Write-Host "OK 安装完成，探针已连接总控（v$($statusJson.agent_version)）。管理台「主机终端」页应已出现本机。" -ForegroundColor Green
  exit 0
}
Write-Warning "安装完成，但探针尚未连接总控（40 秒内 online=false）。排查："
Write-Warning "  1) 稍后重跑: zedr-agent.exe -status -json 看 online 字段"
Write-Warning "  2) 服务端地址是否为目标机可达（回环地址只能本机装本机连）"
Write-Warning "  3) 注册令牌与服务端 HG_SERVER_ENROLL_TOKEN 是否一致"
exit 1
