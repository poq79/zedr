# Z-EDR 探针部署包

本包由服务端构建产出（版本见文件名），包含：

| 文件 | 用途 |
|---|---|
| `zedr-agent.exe` | 终端探针（必装） |
| `zedr-ui.exe` | 桌面托盘/面板（可选，`-WithUI` 时安装） |
| `install-agent.ps1` | 一键安装脚本 |
| `uninstall-agent.ps1` | 卸载脚本 |

## 快速安装（管理员 PowerShell）

```powershell
# 解压后进入本目录
.\install-agent.ps1 -Url http://<总控地址>:8080 -Token <注册令牌> [-Tags 标签1,标签2] [-WithUI]
```

- 注册令牌：管理台「主机终端 → 接入新主机」页（需管理员）；或服务端 `.env` 的 `HG_SERVER_ENROLL_TOKEN`。
- 脚本幂等：重复执行等于按新配置重装。
- 安装动作 = 拷贝到 `C:\Program Files\Z-EDR\bin` → 写入接入配置（exe 同目录 `.env`）→ 注册 Windows 服务（自动启动 + 崩溃自愈）→ 可选托盘自启 → 验证在线。

## 批量下发（运维平台）

任何能以 SYSTEM/管理员执行命令的平台（GPO 启动脚本、Intune、SCCM、PDQ、自研 RMM）都可以：

```
install-agent.ps1 -Url http://<总控>:8080 -Token <令牌>
```

退出码：0 成功上线；2 权限不足；4 参数缺失；其他 = 失败。脚本判断在线用 `zedr-agent.exe -status -json` 的 `online` 字段。

## 卸载

```powershell
.\uninstall-agent.ps1            # 默认保留数据目录（取证优先）
.\uninstall-agent.ps1 -Purge     # 连数据目录一起删
```

## 完整性校验（可选）

下载响应头 `X-ZEDR-Package-SHA256` 为包的 SHA256：

```powershell
Get-FileHash .\zedr-deploy-v<版本>.zip -Algorithm SHA256
```
