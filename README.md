# HostGuard · Windows 主机进程安全检测平台

基于 Go 实现的**主机入侵检测探针（HIDS）**，聚焦"恶意进程检测"这一条主线：
从 Windows 采集 → 五层检测 → 证据链 → 总控汇聚 → 人工闭环处置，全链路可运行、可观测、可运维。

> 设计依据见 [`docs/DETECTION.md`](docs/DETECTION.md)：把"关键词匹配只配做第一层过滤，
> 真正的判定要靠多信号上下文组合"落成可执行的工程结构。

---

## 1. 组成

| 组件 | 二进制 | 说明 |
|---|---|---|
| 总控服务端 | `secserver.exe` | REST API + SQLite + 内嵌管理台；JWT 认证、RBAC、规则下发、告警汇聚 |
| 终端探针 | `secagent.exe` | Windows 采集 + 五层检测 + 本地降噪 + 上报；可装为 Windows 服务 |
| 桌面面板 | `secui.exe` | 原生窗口（WebView2）展示本机态势，无 WebView2 时自动降级为浏览器 |
| 总控后台 | 由 `secserver` 内嵌提供 | 浏览器访问 `http://<server>:8080` |
| 采集自检 | `hgdiag.exe` | 排障工具：验证进程/命令行/账号/签名/网络等采集能力是否正常 |

```
┌──────────────┐   HTTPS/HTTP    ┌──────────────────┐
│  secagent    │ ──────────────► │  secserver       │
│  (每台终端)  │  告警/心跳/规则  │  REST + SQLite   │
└──────┬───────┘                 └────────┬─────────┘
       │ 127.0.0.1:8843                   │ 浏览器
       ▼                                  ▼
┌──────────────┐                 ┌──────────────────┐
│  secui 桌面  │                 │  总控管理后台     │
└──────────────┘                 └──────────────────┘
```

---

## 2. 快速开始

### 2.1 环境要求

- Windows 10 / Server 2016 及以上（64 位）
- Go 1.22+（本项目在 go1.27.3 上验证）；**不需要 CGO / gcc**
- 桌面面板可选依赖：Microsoft Edge WebView2 Runtime（Win11 与新版 Win10 通常自带）

### 2.2 编译

```bash
go mod download

# 注意：不要加 -s -w。剥离符号的 PE 会呈现"加壳"特征，
# 容易被终端安全软件判定为可疑并拦截/隔离（本项目实测踩过这个坑）。
go build -ldflags "-X main.version=0.1.0" -o bin/secserver.exe ./cmd/server
go build -ldflags "-X main.version=0.1.0" -o bin/secagent.exe  ./cmd/agent
go build -ldflags "-X main.version=0.1.0" -o bin/secui.exe     ./cmd/desktop
go build -ldflags "-X main.version=0.1.0" -o bin/hgdiag.exe    ./cmd/hgdiag
```

或直接 `bash scripts/build.sh`。

### 2.3 配置

```bash
cp .env.example .env
# 至少修改这两项：
#   HG_SERVER_JWT_SECRET   至少 32 字节随机串（openssl rand -hex 32）
#   HG_SERVER_ENROLL_TOKEN 终端注册令牌，需与探针侧一致
```

所有配置项见 [`.env.example`](.env.example)，启动时会集中校验、缺失或非法立即退出。

### 2.4 运行

```bash
# 1) 总控服务端（首次启动会打印初始管理员密码与注册令牌，仅打印一次）
./bin/secserver.exe

# 2) 终端探针
./bin/secagent.exe

# 3) 桌面面板（可选）
./bin/secui.exe
```

- 管理台：<http://127.0.0.1:8080>（账号见启动日志）
- 本地面板：<http://127.0.0.1:8843>（仅回环可访问）

### 2.5 装成 Windows 服务（需管理员）

安装时会自动配置**失败恢复策略**（5s / 10s / 30s 三级退避重启，1 天重置）。
没有这一步，一次 `taskkill /f` 就能让防护永久失效，而系统看起来一切正常。
若该步骤失败，安装程序会打印手动设置用的 `sc failure` 命令。

> 服务的工作目录是 `C://Windows//System32`，因此 `.env` 必须放在
> **可执行文件同目录**（或改用系统环境变量）。v0.2 起配置加载已改为
> 优先查找 exe 所在目录，修复了"服务模式下配置静默失效"的问题。

```powershell
.\bin\secagent.exe -install     # 安装并启动，开机自启
.\bin\secagent.exe -uninstall   # 停止并卸载
```

---

## 3. 检测能力

五层流水线，每层都向最终结论贡献**可解释的证据**，而不是黑盒打分：

| 层 | 名称 | 手段 | 分值上限 | 典型命中 |
|---|---|---|---|---|
| L1 | 静态指纹 | SHA256 黑名单、Authenticode 签名（含 catalog 目录签名）、路径信誉 | 45 | 已知样本、签名被篡改、无签名且落在可写目录 |
| L2 | 关键词 | Aho-Corasick 多模式一次扫描 | 40 | `vssadmin delete shadows`、`-EncodedCommand`、矿池协议 |
| L3 | 行为规则 | 36 条内置规则（Sigma 风格 JSON DSL，可下发/可热更新） | 55 | Office→shell、伪装系统进程、关闭 Defender |
| L4 | 血缘图 | 父子链频次基线 + 稀有组合 + 孤儿进程 + 攻击链组合 | 30 | "这个父进程从不拉起这东西" |
| L5 | 融合决策 | 分阈值定级 + 白名单 + 连续重复抑制 + 冷启动静默 | — | ≥70 恶意 / ≥38 可疑 |

**降噪设计**（对应报告的"五级降噪"）：

1. 白名单前置：哈希 / 路径 / 签名主体 / 父子对 / 命令行片段，命中即不进引擎；
2. 冷启动静默期：默认 5 分钟内只放行"恶意级"，先攒够基线再放开可疑级；
3. 本地指纹去重：同指纹 5 分钟只报一次；
4. 服务端聚合：同指纹重复上报折叠为一条并累加计数，展示"影响主机数"；
5. 人工闭环：后台标记误报 + 一键加白，形成回流。

**实测资源占用**（本机 250+ 进程，轮询 2s）：

```
CPU 0.20% · 内存 11.9 MB · 平均单进程检测 32~47 ms · 快照 7.7 ms · TCP 表 2.0 ms
```

---

### AI 分析能力（v0.4）

主流 EDR 的 AI 已经收敛成"自然语言狩猎 + 告警研判 + 时间线叙事"，
所以差异点不在"有没有 AI"，而在四件更硬的事。本项目的选择：

| 方向 | 主流做法 | 我们的做法 |
|---|---|---|
| 可核查性 | 输出叙事文本 | **每条结论强制引用证据编号**，编造的引用直接作废 |
| 抗操纵 | 提示词里叮嘱 | **检测命令行/路径里的指令注入**，命中即作为一条独立证据计分 |
| 可用性 | 依赖云端模型 | **推理后端可插拔**，无模型时用确定性引擎产出同结构结论 |
| 成本 | 按计算单元计费 | **每小时 token 硬上限**，触顶自动降级 + 结果缓存 |

实测（无外部模型，走内置确定性引擎）：

- 研判一条恶意告警 → `malicious` / 置信度 0.87 / **结论全部可溯源** / 建议动作全部标记"需人工确认"
- 命令行塞入 `ignore previous instructions` 的样本 → 识别 3 处注入，
  追加证据"对抗性内容：试图操纵分析引擎（35 分）"，结论仍为 `malicious`
- 自然语言检索"最近24小时未签名的高分告警" → 解析为 `signed=false AND score>=70`，命中 9 条

配置（`HG_AI_PROVIDER`）：`none` 用内置引擎；`openai` 接任何 OpenAI 兼容服务
（OpenAI / DeepSeek / 通义 / Kimi / vLLM / Ollama）。详见 [docs/AI.md](docs/AI.md)。

### 本地接口的访问控制（v0.3）

桌面 UI 通过 `127.0.0.1:8843` 与探针通信。这个接口原先没有任何认证——
**任何本机进程、甚至浏览器里的任意网页**都能调 `/api/local/allowlist`
把攻击载荷永久加白，或读走全部告警与进程清单。

现在有三层防护：

| 防护 | 作用 |
|---|---|
| 回环地址校验 | 拒绝经转发到达的请求 |
| Origin 校验 | 切断浏览器跨站请求（最现实的攻击路径） |
| 访问令牌 | 令牌存于数据目录 `local.token`（0600），请求需携带 `X-HG-Token` |

桌面宿主会自动把令牌交给页面并在地址栏抹掉；浏览器直接访问时会弹出令牌输入框。

> 同用户身份的进程仍可读取该令牌文件——这是操作系统的信任边界，
> 用户态无法彻底解决。配合前两层，已切断"网页调本地接口"这条实际攻击链。

### 行为采集层（v0.2）

只看进程创建有两个结构性盲区：不知道文件从哪来，也看不到驻留。v0.2 补了：

| 采集源 | 机制 | 产出的信号 | 实测 |
|---|---|---|---|
| 文件落地监控 | `ReadDirectoryChangesW` 订阅 8 个高价值目录 | `DROP-001` 落地即执行（+5 ~ +40） | `%TEMP%` 写入未签名 PE 后立即执行 → 40 分，判定恶意 |
| 持久化项监控 | 枚举 Run/RunOnce、启动目录、自启动服务、计划任务、Winlogon、IFEO | `P-001` 持久化变更（28 ~ 72 分） | 新增指向 `%TEMP%` 的 Run 项 → 72 分 / T1547.001 |

两条设计约束：

- 落地监控只对"可写目录 + 无有效签名 + 短时间内被执行"给高分，
  装到 `Program Files` 后运行是正常安装行为，只给 5 分；
- 持久化监控**首次运行只建基线、不告警**（本机 422 项），
  之后只判断新增与改写——否则第一次启动就会刷屏。

### 双视角打磨（v0.8）

**普通用户**：告警自带「给你的说明」（发生了什么/意味着什么/建议你）；
`secagent -status` 服务器 SSH 一屏状态；服务延迟自启动不拖慢开机；
`-uninstall -purge` 干净卸载；`/api/local/privacy` 隐私一键透明
（采什么/不采什么/怎么脱敏）。

**安全管理者**：登录失败/锁定进审计（SIEM 可见暴力破解）；/metrics 版本分布
（升级进度可见）；**告警完整性链**（每日摘要归档+校验，防内部删改，
ok/purged/tampered 三态判定）；白名单导出/导入（灾备迁移）；终端队列丢弃
计数上报（告警黑洞可见）。

### 企业运营能力（v0.7）

以"运营人员 + 安全经理"双视角补齐的 11 项能力（详见 docs/TEST-REPORT 第十三轮）：

| 痛点 | 能力 |
|---|---|
| 初始密码无法轮换 | **改密码**（侧边栏入口），强制强度策略（≥10 位三类字符），改密即吊销全部会话 |
| 暴力破解无防线 | 登录失败 5 次锁 15 分钟 |
| 数据随时归零 | **每日自动备份**（VACUUM INTO 快照，保留 7 份） |
| 时间线因 NTP 漂移失真 | 心跳带时钟偏移检测，主机页徽标提示 |
| 通知风暴 | Webhook 按严重度过滤（默认只推 high+，只推未处置） |
| SIEM 接入要开发 | **Syslog CEF/UDP 输出**（Splunk/QRadar 零开发接入） |
| 横向移动看不到 | **跨主机爆发检测**：同一哈希 ≥3 主机同窗口出现，事件页顶部红条 |
| 响应快慢靠感觉 | **MTTR 指标**（概览卡 + /metrics） |
| 误报治理没方向 | **规则误报率排行**（≥5 次处置才参与，防小样本噪音） |
| 给管理层的汇报靠手拼 | **运营周报页**：一页纸 + 打印/存 PDF |
| 逐台改探针配置 | **策略集中下发**：扫描间隔热生效、采集引擎冷生效，随规则包签名下发；终端本地显式配置优先 |

### 生产化能力（v0.6）

| 能力 | 端点/入口 | 说明 |
|---|---|---|
| **事件聚合** | 管理台「事件」页 / `GET /api/v1/incidents` | 未处置告警按"同主机 + 相邻间隔 ≤30min"聚类成攻击链事件：峰值严重度、MITRE 组合、时间跨度、一键跳转成员告警 |
| **批量处置** | `POST /api/v1/alerts/bulk-status` | 单条审计记录覆盖整批（谁/何时/处置了什么） |
| **Webhook 推送** | `HG_SERVER_WEBHOOK_URL` | 告警实时外发，`X-HG-Signature: sha256=<HMAC>` 可验签；有界队列满即丢（旁路不反压主链路），丢弃数在 /metrics 可见 |
| **Prometheus 指标** | `GET /metrics` | 主机/告警/严重度分布/webhook 成败/Go runtime，手写文本格式零依赖 |
| **CSV 导出** | 告警页「导出 CSV」按钮 | 按当前筛选导出（与页面所见一致），含 BOM/公式注入防护/5000 行上限标注，导出进审计 |
| **前端框架化** | `vendor/alpine.min.js` | Alpine 3.17 经 npm SHA512 校验后本地嵌入（无 CDN）；新组件（Ctrl+K 命令面板、事件页）用声明式绑定，既有视图渐进迁移 |
| **命令面板** | `Ctrl+K` | 键盘直达任意页面与高频操作（筛选/导出/紧凑视图/帮助） |
| **UI 细节** | — | 骨架屏加载、可排序表格列（时间/分值/严重度）、登录页品牌化、事件卡语义色边 |

### 运营效率与性能（v0.5）

- **探针 CPU 3.07% → 1.38%**（自适应扫描退避 + 富化快速路径 + 1MB 哈希缓冲），内存 33.6MB 稳定，句柄零泄漏；
- **管理台运营层**：批量处置、键盘导航（`j/k/x/a//d?`）、保存视图、同主机时间线、紧凑密度（`d`）；
- **计划任务深度解析**：不再只记 XML 路径——Command/Arguments/RunLevel/Trigger 全部提取，
  "最高权限 + 开机触发"组合直接进入评分；基线 schema 版本化避免升级误报风暴。

完整的性能预算、兼容性矩阵与**"研究后判定不做"清单**（ETW/内核驱动/PostgreSQL/mTLS/ML，
各含理由与替代方案）见 [docs/TRADEOFFS.md](docs/TRADEOFFS.md)。

## 4. 自测结果

完整报告见 [`docs/TEST-REPORT.md`](docs/TEST-REPORT.md)。要点：

- **攻击场景 14 例**：检出 9 例，2 例不可观测（EICAR 无法执行 / 极短命进程），
  3 例为单弱信号（`-enc`、`schtasks /create`、`reg add`）——刻意的降噪取舍，非缺陷
- **稳态误报**：本机 256 个真实进程里仅 1 个越过可疑阈值（桌面上的未签名 GUI 工具）
- **性能**：CPU 0.22%、内存 16MB、单进程检测 26ms、服务端接入 871 条/秒
- 测试中发现并修复 6 个真实缺陷，详见报告第五章

```bash
bash scripts/simulate_detection.sh    # 最小验证（4 个场景，约 40 秒）
python scripts/scenarios.py all       # 完整评估（场景 + 误报 + 性能 + 压测）
python scripts/scenarios.py fp        # 只看误报面
```

> 判定口径：直接读引擎给出的 `score / verdict / suppressed`，而不是"有没有新告警"。
> 这样才能区分"真漏检"和"检出但被去重抑制"。

---

## 5. 目录结构

```
hostguard/
├── cmd/
│   ├── server/          # 总控服务端入口
│   ├── agent/           # 探针入口（含 Windows 服务安装）
│   ├── desktop/         # 桌面面板入口（WebView2）
│   └── hgdiag/          # 采集层自检工具
├── internal/
│   ├── model/           # 探针与服务端共享的领域模型 + 线协议
│   ├── ioc/             # 编码存储的 IOC（避免产物被误判）
│   ├── rules/           # 规则 DSL 求值器 + 36 条内置规则
│   ├── platform/        # config / logx / apperr / httpx / idgen
│   ├── agent/
│   │   ├── winapi/      # Win32/NT 原生调用（进程/PEB/令牌/模块/TCP/签名）
│   │   ├── collect/     # 增量采集与血缘回溯
│   │   ├── enrich/      # 哈希、签名、路径分类（带缓存）
│   │   ├── baseline/    # 父子链频次基线
│   │   ├── allow/       # 白名单
│   │   ├── detect/      # 五层检测引擎
│   │   ├── uplink/      # 服务端通信（有界队列 + 失败重试）
│   │   ├── localapi/    # 本地接口 + 内嵌桌面 UI
│   │   ├── state/       # 内存视图
│   │   └── app/         # 组装与运行时循环
│   └── server/
│       ├── domain/      # 服务端实体
│       ├── repository/  # 仓储接口 + SQLite 实现（含迁移）
│       ├── service/     # 业务逻辑（不依赖 HTTP）
│       ├── auth/        # JWT、bcrypt、RBAC
│       ├── api/         # 控制器（路由、中间件、SSE）
│       ├── web/         # 内嵌管理台前端
│       └── app/         # 组装与后台维护任务
├── scripts/             # 构建、受控验证、告警查看
└── docs/DETECTION.md    # 检测体系设计说明
```

分层约束：控制器不含业务逻辑；服务层不依赖 `net/http`；仓储层对上层只暴露接口。

---

## 6. 主要接口

### 终端侧（API-Key，`X-Agent-Id` + `Authorization: Bearer <secret>`）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/agents/enroll` | 注册（预共享令牌），返回 agent_secret |
| POST | `/api/v1/agent/heartbeat` | 心跳 + 拉取待执行指令 |
| POST | `/api/v1/agent/alerts` | 批量上报告警（单批 ≤500） |
| GET | `/api/v1/agent/rules` | 拉取规则整包（支持 ETag/304） |
| POST | `/api/v1/agent/commands/result` | 指令回执 |

### 管理台（JWT，`Authorization: Bearer <access>`）

| 方法 | 路径 | 权限 |
|---|---|---|
| POST | `/api/v1/auth/login` `/refresh` `/logout` | 公开 |
| GET | `/api/v1/dashboard` | viewer+ |
| GET | `/api/v1/alerts` `/alerts/{id}` | viewer+ |
| POST | `/api/v1/alerts/{id}/status` | analyst+ |
| GET | `/api/v1/hosts` `/hosts/{id}` | viewer+ |
| POST | `/api/v1/hosts/{id}/commands` | analyst+ |
| GET/POST | `/api/v1/rules`、`/rules/{id}/toggle` | viewer / analyst+ |
| GET/POST/DELETE | `/api/v1/allowlist` | viewer / analyst+ |
| GET | `/api/v1/audit` | viewer+ |
| GET/POST | `/api/v1/users` | admin |
| GET | `/api/v1/stream/alerts` | SSE（一次性票据鉴权） |
| GET | `/health` `/ready` | 公开 |

---

## 7. 测试

```bash
go vet ./...                    # 静态检查（应为空）
go test ./...                   # 单元 + 集成测试
bash scripts/simulate_detection.sh   # 端到端受控验证（需先启动服务端与探针）
```

- `internal/agent/detect`：关键词/AC 自动机/规则编译/白名单/融合定级
- `internal/server/api`：跑在临时 SQLite 上的完整集成测试（登录、RBAC、注册、上报、聚合去重、处置、审计）

---

## 8. 已知边界（重要）

1. **采集是用户态轮询**，默认 2s 一轮。存活时间短于一个轮询周期的进程可能漏检（TOCTOU）。
   生产环境应替换为 ETW `Microsoft-Windows-Kernel-Process` 或 WMI `Win32_ProcessStartTrace` 订阅。

   已尝试用 ETW 实时事件根治这个问题：`winapi/etw.go` 实现了
   `Microsoft-Windows-Kernel-Process` 订阅，但在 Windows Server 2022 上
   `OpenTrace` 持续返回 `ERROR_INVALID_NAME`，**验证未通过**。
   因此它通过 `etw` 构建标签隔离、默认不编译，不进主干。
   现阶段用文件落地监控来间接补盲（能捕获"落地后存活到被执行"的样本）。

   采集层已做成**可插拔**（`collect.Source`），内置两套实现，可运行时切换：

   | `HG_AGENT_COLLECTOR` | 实现 | 特点 |
   |---|---|---|
   | `auto`（默认） | 优先 NtQuery，探测失败自动回退 Toolhelp32 | 推荐 |
   | `ntquery` | `NtQuerySystemInformation` 一次系统调用 | 快 2.6×，自带创建时间（可识别 PID 复用） |
   | `toolhelp` | Toolhelp32 快照（旧引擎） | 兼容性最好，作为兜底 |

   切换只需改环境变量、重启探针，无需重新编译——这正是为了应对新老 Windows
   版本与安全软件干预带来的差异。
2. **不做内核态阻断**。当前只告警与可选终止（`HG_AGENT_KILL_ENABLED`，默认关闭，且需服务端同时开启）。
3. **签名校验不含在线吊销检查**，走本地缓存以保证性能。
4. **默认不检测文件写入行为**，只覆盖进程创建及其上下文。
5. **IOC 表为内置样例**，生产应替换为服务端下发的 IOC 库。

---

## 9. 工程注意事项（都是踩过的坑）

- **不要用 `-ldflags "-s -w"`**：剥离符号后的 PE 在多数终端安全软件看来接近"加壳样本"，会被直接拦截，导致链接产物瞬间消失、只报 `Access is denied`。
- **IOC 字面量必须编码存储**（见 `internal/ioc`）：恶意工具名与攻击命令片段以明文出现在二进制里，会同样触发文件扫描拦截，也方便攻击者反查检测逻辑。
- **签名校验必须覆盖 catalog**：Windows 自带的 exe/dll 大量只做目录签名（`.cat`），只调 `WinVerifyTrust(WTD_CHOICE_FILE)` 会把 `notepad.exe`、`cmd.exe` 误判为"无签名"，进而制造大批误报。
- **模块未签名判定不能只看目录**：必须对模块真正验签，否则 git bash、Node 这类合法签名软件的 DLL 会被整体误判。
- **令牌不入 localStorage、不进 URL**：访问令牌仅存内存，刷新令牌走 HttpOnly Cookie；SSE 用 60 秒一次性票据，避免把凭证写进 URL 与代理日志。

---

## 10. 后续路线

| 阶段 | 目标 |
|---|---|
| P1 | 采集换 ETW 实时事件，消除轮询漏检；补文件落盘与注册表行为 |
| P2 | 命令行语义向量 + 轻量 XGBoost 分类器；父子链条件概率模型（ProblemChild 思路） |
| P3 | 跨主机图关联与攻击链还原；IOC/模型服务端下发与灰度 |
| P4 | 处置动作扩展（隔离进程/阻断网络），配合内核态同步阻断 |
