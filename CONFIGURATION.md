# Z-EDR 配置树

> 全部配置来自环境变量（`HG_*`，双侧 .env；见 `.env.example` 逐键注释）。
> 本文档是**域分组导航 + 配置机制判据**，不是逐键手册——逐键语义以
> `.env.example` 为准（两边同步维护，改键必改两处）。
>
> 生成口径：2026-11-22 盘点，132 个唯一键。架构评审 P2"配置树"落地。

## 配置机制的两种口径（判据）

| 机制 | 存储 | 生效方式 | 判据 | 现有键 |
|---|---|---|---|---|
| **env 静态配置** | 进程 .env / 环境变量 | 启动时集中校验、快速失败；改后重启 | 基础设施与安全底线类（路径/密钥/开关/阈值） | `HG_*` 全部 132 键 |
| **settings KV**（服务端） | SQLite settings 表 | 登录/使用时实时读取，热生效 | "策略类"——运维在管理台频繁调整、且改错不致命的运营策略 | `mfa_require_admins`、`mfa_require_all`（MFA 强制策略） |

**新增配置先问一句**：运维会经常在管理台调它吗？会 → settings KV
（配管理台 UI + 审计）；不会 → env（配 `.env.example` + loader 行 +
app→service 透传，三处缺一 env 就静默失效——两次真实事故的教训）。

## 服务端域（zedr-server）

| 域 | 关键键 | 说明 |
|---|---|---|
| 监听与 TLS | `ADDR` `DB_PATH` `CORS_ORIGINS` `TLS_CERT/KEY` `TLS_TERMINATED` | 生产模式 TLS 与 TERMINATED 二选一，都没有启动即拒 |
| 认证与会话 | `JWT_SECRET` `ACCESS_TTL` `REFRESH_TTL` `COOKIE_SECURE` `BOOTSTRAP_USER/PASSWORD` | 密钥派生链：JWT_SECRET 为根，RULE_SIGN/SETTING_ENC/AUDIT_SEAL 留空自动派生 |
| 限流 | `RATE_LIMIT_RPS/BURST` `LOGIN_RPS/BURST`（独立桶）`INGEST_ALERT_RPS/BURST/MAX_INFLIGHT` | 登录桶独立于全站桶，勿合并 |
| 告警管线 | `DUP_WINDOW` `RETENTION_DAYS` `RETENTION_MAX_MB` `OPEN_ALERT_TTL` | OpenAlertTTL 默认 0=禁用（自动替值班做决定的事必须显式开） |
| 通知渠道 | `WEBHOOK_URL/SECRET/TIMEOUT/MIN_SEVERITY` `SYSLOG_ADDR` `FEISHU/DINGTALK/SLACK/SMTP_*` `CONSOLE_URL` | MIN_SEVERITY 是统一门槛（默认 high）；IM 渠道另有 dedup/限速内置 |
| 响应处置闸（默认全关） | `KILL_ENABLED` `QUARANTINE_ENABLED` `DRILL_ENABLED` `UPGRADE_ENABLED` `ISOLATION_ENABLED` | 全部需与探针侧 `HG_AGENT_*_ENABLED` 成对开启（双层开关）；ISOLATION 仅 admin 可发起 |
| 自升级/部署 | `UPGRADE_FILE/VERSION/WAVE_SIZE/WAVE_TIMEOUT/BATCH_PERSIST` `DEPLOY_PACKAGE/VERSION` | 批次持久化默认开（重启恢复为暂停态） |
| 失联与简报 | `SENSOR_OFFLINE_ALERTS/SEVERITY` `BRIEFING_PUSH/HOUR` | 简报推送默认关（主动推手机的消息一律显式打开） |
| 隔离/文件防线 | `LIVEQUERY_ENABLED/FILEREAD/COLLECT` | 只读默认开、文件预览默认关、取证打包默认关（三档暴露面） |
| MCP 对外 | `MCP_ENABLED` `MCP_TOKEN` | 独立 Bearer Token，默认关 |
| AI 引擎 | `AI_PROVIDER/BASE_URL/API_KEY/MODEL/TIMEOUT/HOURLY_TOKEN_BUDGET` `AI_AGENT_MAX_STEPS/TOOL_TIMEOUT` `AI_ZEROCLICK(+MAX_PER_HOST)` | 引擎细节（槽位/提示词/拨测）在管理台「AI 平台」配置中心，env 只是引导值 |
| 模板/审计密钥 | `SETTING_ENC_KEY` `AUDIT_SEAL_KEY` | 见认证域的派生链说明 |

## 探针域（zedr-agent）

| 域 | 关键键 | 说明 |
|---|---|---|
| 接入 | `SERVER_URL` `ENROLL_TOKEN` `TAGS` `DATA_DIR` `LOCAL_ADDR` | `-install` 安装时落 exe 同目录 .env |
| 传输安全 | `REQUIRE_TLS` `TLS_CA_FILE` | auto=非回环强制 https |
| 采集 | `COLLECTOR` `SCAN_INTERVAL` `FULL_RESCAN` `MAX_HASH_MB` `ADAPTIVE_SCAN` `WARMUP` | COLLECTOR=auto 双引擎回退 |
| 行为检测（默认全开、单侧终端开关） | `FILEWATCH` `USN_POLL(+INTERVAL)` `USN_CATCHUP` `NETWATCH` `FILE_DEFENSE` `REGWATCH` `EVTLOG` `MEMWATCH(+INTERVAL)` `USBWATCH` `CHAIN` | 关闭任一即关一整条检测线；阈值覆盖 `NET_SCAN_PORTS/SWEEP_IPS/LATERAL_IPS/LATERAL_PORTS` |
| 处置闸（与 server 成对） | `KILL_ENABLED` `QUARANTINE_ENABLED` `DRILL_ENABLED` `UPGRADE_ENABLED` `ISOLATION_ENABLED` | release/解除类动作不受终端闸约束（永远有解救路径） |
| 资产与侦查 | `INVENTORY` `RECON_PROBE` `MEMSCAN_ENABLED` `BASELINE_LEARN` | RECON_PROBE=false=纯被动 |
| 韧性 | `OFFLINE_QUEUE` `MEM_LIMIT_MB` `TUNNEL_ENABLED` | spool 断网缓存/软内存上限/零监听隧道 |
| 策略下发 | （server 侧）`HG_AGENT_POLICY_SCAN_INTERVAL/COLLECTOR` | 服务端一处配置随签名包下发全部探针 |

## 探针历史遗留键（更名保留）

`HG_AGENT_POLICY_*`（server 侧下发用）、`HG_AGENT_MEMSCAN_ENABLED` 等
模块键名沿用 `HG_` 前缀与 `HG-` 规则 ID 前缀——2026 项目更名（Z-EDR）
时刻意保留（老探针兼容），新增键统一用 `HG_`，没有 `ZEDR_` 二套前缀。

## 生命周期速查

- **启动校验**：loader 集中校验（范围/互斥），违规直接拒绝启动；
  新键三处自查：`.env.example` → `LoadConfig` loader 行 → app→service 透传行。
- **热生效**：settings KV（MFA 策略）；`HG_AGENT_POLICY_*`（签名包下发）；
  AI 配置中心（Engine.ApplyConfig 免重启）。
- **管理台覆盖**：AI 平台页（模型/槽位/提示词/预算/缓存）保存后以
  配置中心为准，env 仅是未保存时的引导值。
