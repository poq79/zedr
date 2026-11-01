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

## 4. 受控验证（不下载任何外部载荷）

```bash
bash scripts/simulate_detection.sh
```

该脚本只用**本机自造样本**验证检测链路，安全边界明确：

- 复制自己的 `hgdiag.exe` 改名为 `svchost.exe` / `nmap.exe`（内容是自己的诊断工具，零风险）
- 用 `echo` + 回环 `ping` 构造可疑命令行（不执行任何实际操作）
- 用行业标准 EICAR 测试串验证静态哈希层（该字符串不含可执行代码）

实测结果：

| 样本 | 命中 | 结论 | 分值 |
|---|---|---|---|
| `%TEMP%\svchost.exe` | HG-016 | 可疑（伪装系统进程） | 68 |
| `%TEMP%\nmap.exe` | N-009 + HG-019 + HG-021 | 恶意 | 98 |
| `cmd /c echo wevtutil cl ...` | K-022 / HG-034 | 恶意 | 83 |
| `chfsgui.exe`（本机真实未签名应用） | HG-021 + HG-031 | 可疑 | 55 |

> 脚本给样本进程加了 `-hold 12s`：探针默认 2 秒一轮轮询，而这类诊断进程本身只活 1–2 秒，
> 不加保活会偶发漏检。这正说明"用户态轮询存在 TOCTOU 盲区"，也是换 ETW 的直接理由。
>
> 告警经服务端入库后，会通过 SSE 实时推送到管理台（已实测 `event: alert` 帧携带完整告警负载）。

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
   生产环境应替换为 ETW `Microsoft-Windows-Kernel-Process` 或 WMI `Win32_ProcessStartTrace` 订阅——这部分已在架构上预留（采集层与检测层通过 `collect.ProcessInfo` 解耦）。
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
