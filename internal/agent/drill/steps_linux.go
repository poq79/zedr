//go:build linux

// 五个演练步骤的 Linux 实现（全部自造样本、零真实恶意内容、零真实外联：
// 回环/TEST-NET-3 拨号、自身写删演练文件）。Windows 口径见 steps_windows.go；
// 调度与报告结构在 drill.go。
package drill

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"zedr/internal/platform/redact"
)

// Linux 演练文件与内容：真实 cron 语法（/etc/cron.d 六字段 + 用户列），
// 调度位取 2 月 31 日（永不存在的日期，dow=* 无 dom 可配对）+ /bin/true
// 双保险零执行。内容必须可被持久化基线的 cron 解析器枚举成条目
// （注释行会被解析器跳过，所以正文放一条可枚举的真实格式行）。
const (
	drillCronPath = "/etc/cron.d/zedr-drill-persist"
	drillCronTmp  = "/tmp/zedr-drill-cron"
	drillCronBody = "# zedr-drill 演练条目：写入后立即删除，不执行任何命令\n" +
		"0 3 31 2 * root /bin/true\n"
)

// 演练拨号参数：TEST-NET-3（RFC 5737，不可路由），两波端口区间刻意隔开
// （第二波必须是"全新端口"才计入扇出，见 runWaves 注释）。
const (
	drillScanTarget  = "203.0.113.9"
	drillScanWave1Lo = 45100
	drillScanWave1Hi = 45119 // 20 端口：建基线（< NW-001 阈值）
	drillScanWave2Lo = 45300
	drillScanWave2Hi = 45359 // 60 端口：> NW-001 默认阈值 40（2026-11-14 上调）留余量
)

// stepProcChain 采集管线健康检查：拉起一个活 5s 左右的 sh，轮询进程表
// 确认"新进程被采集管线捕获"。这是唯一不匹配规则的步骤。
func stepProcChain(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepProcChain, ExpectedRule: PipelineSentinel}
	if deps.ProcSnapshot == nil {
		return skip(StepProcChain, "ProcSnapshot 未接线")
	}
	// 基线：演练前已存在的 PID 不算"新出现"。
	base := make(map[uint32]struct{}, 512)
	for _, p := range deps.ProcSnapshot() {
		base[p.PID] = struct{}{}
	}
	// 自造样本：echo 后 sleep 5，把 sh 生命周期撑过采集轮询周期，
	// 规避用户态轮询固有的 TOCTOU 盲区（仓库 5.3 的教训）。
	if _, err := spawnDetached("sh", "-c", "echo zedr-drill; sleep 5"); err != nil {
		res.Note = "spawn 失败: " + err.Error()
		return res
	}
	var observed uint32
	hitAt, ok := awaitHit(ctx, func() bool {
		for _, p := range deps.ProcSnapshot() {
			if p.PID == deps.SelfPID {
				continue // 自身/自身子树之外才叫"新被捕获"
			}
			if _, seen := base[p.PID]; seen {
				continue
			}
			// /proc/[pid]/stat 的 comm 取自 execve 传入路径的 basename：
			// exec.Command("sh") 经 PATH 解析到 /usr/bin/sh，comm 恒为
			// "sh"（即便发行版把它符号链接到 dash）。
			if p.Name == "sh" {
				observed = p.PID
				return true
			}
		}
		return false
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	if ok {
		res.Note = fmt.Sprintf("新 sh（PID %d）已出现在进程表，采集管线健康", observed)
	} else {
		res.Note = "10s 内未观察到新 sh——采集管线可能停摆或样本过快退出"
	}
	return res
}

// stepPortScan 网络行为检测（Linux 口径）：向 TEST-NET-3 保留网段发起
// 仅 SYN 的连接尝试，零数据传输、零真实外联。Go 原生拨号，不需要子进程
// （Windows 版要 powershell 才有"挂住不关"的脚本化手段；Linux 由探针
// 进程内 goroutine 并发拨号等价实现）。
func stepPortScan(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepPortScan, ExpectedRule: "NW-001/NW-004"}
	if !deps.NetWatchEnabled {
		return skip(StepPortScan, "HG_AGENT_NETWATCH 未启用，网络行为检测不可用")
	}
	if deps.AlertsSince == nil {
		return skip(StepPortScan, "AlertsSince 未接线")
	}

	// 为什么必须两波（与 Windows 版同因）：netwatch 对首次 sighting 的
	// 进程只记基线不记事件（防启动风暴）。瞬时把全部拨号发完，等采样器
	// 第一次看到时整批落进基线，永远零事件——Windows 侧 E2E 实测踩过的坑。
	// 第一波 20 端口只为建基线，停 6s（≥3 个采样 tick）后第二波 60 个
	// 全新端口才会计入扇出。挂住不关的等价物：DialContext 对不可路由
	// 地址会阻塞在 SYN 重传（内核 ~2min），并发拨号让全部端口同时在途；
	// 生命周期全部交给 heldDials：两波节奏走完统一 Close，step 返回时
	// ctx 取消兜底中止在途拨号——两条路都保证演练不留散落 socket。
	held := newHeldDials(ctx)
	go held.runWaves()

	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "NW-001", "NW-004")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "对 TEST-NET-3 不可路由网段的 SYN 扇出已被网络行为检测捕获（零真实外联）"
	} else {
		// 诚实边界（2026-11-14 实况）：netwatch 的 Observe 三遍处理都排除
		// 探针自身 PID（自升级/隧道连接不参与检测），且接线层目前仅在
		// Windows 编译——探针进程内的演练拨号当前不可见，本步在 Linux 上
		// 预期 miss 直到接线面把这两处打开。
		res.Note = "60s 内未出现 NW-001/NW-004 告警（阈值未达到、netwatch 未接线，或探针自进程连接被自排除规则忽略）"
	}
	return res
}

// heldDials 管理演练拨号的生命周期：拨号成功即登记，收尾统一关闭；
// 收尾晚于拨号返回时由 done 标记让 goroutine 自关，不留泄漏窗口。
type heldDials struct {
	ctx   context.Context
	mu    sync.Mutex
	conns []net.Conn
	done  bool
}

func newHeldDials(ctx context.Context) *heldDials { return &heldDials{ctx: ctx} }

// dialHoldTimeout 只是拨号自身的保底（远超两波节奏总时长）；真正的
// 收敛靠两波收尾的统一 Close 与 step ctx 取消。
const dialHoldTimeout = 90 * time.Second

// dial 单端口异步拨号：成功后登记（收尾统一关）；若收尾已完成则立即
// 自关，避免"连接建立晚于收尾"的窗口把 socket 泄漏到演练之外。
func (h *heldDials) dial(port int) {
	go func() {
		addr := net.JoinHostPort(drillScanTarget, strconv.Itoa(port))
		c, err := (&net.Dialer{Timeout: dialHoldTimeout}).DialContext(h.ctx, "tcp", addr)
		if err != nil {
			return // ctx 取消/不可路由超时：无连接需要清理
		}
		h.mu.Lock()
		if h.done {
			h.mu.Unlock()
			_ = c.Close()
			return
		}
		h.conns = append(h.conns, c)
		h.mu.Unlock()
	}()
}

// wait 等待 d 或 ctx 结束，返回 false 表示 ctx 已结束（应立即收尾）。
func (h *heldDials) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-h.ctx.Done():
		return false
	}
}

// runWaves 两波节奏：第一波建基线 → 停 6s（≥3 个采样 tick，让采样器把
// 第一波"看见"并记入基线）→ 第二波全新端口计入扇出 → 停 15s 留足采样 →
// 统一 Close。ctx 提前结束（命中提前返回/超时）立即收尾，不等满节奏。
func (h *heldDials) runWaves() {
	for p := drillScanWave1Lo; p <= drillScanWave1Hi; p++ {
		h.dial(p)
	}
	if !h.wait(6 * time.Second) {
		h.closeAll()
		return
	}
	for p := drillScanWave2Lo; p <= drillScanWave2Hi; p++ {
		h.dial(p)
	}
	h.wait(15 * time.Second)
	h.closeAll()
}

func (h *heldDials) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.done = true
	for _, c := range h.conns {
		_ = c.Close()
	}
	h.conns = nil
}

// stepServiceEvt 事件日志层（Linux 口径）：Linux 无 SCM，Windows System
// 7045 服务安装事件没有等价信号源——systemd 单元安装是文件落盘，走
// 持久化基线层（由 reg_run 步骤的 Linux 等价演练覆盖）。记 skipped 而非
// 失败："没测"与"没测出来"必须可区分（演练报告硬要求）。
func stepServiceEvt(ctx context.Context, start time.Time, deps Deps) StepResult {
	return skip(StepServiceEvt, "Linux 无 SCM/7045 等价信号，该步骤跳过")
}

// stepRegRun 持久化检测（Linux 口径）：向 cron.d 写演练文件（Linux 等价的
// 用户态持久化位，T1053.003；与 Windows 写 Run 键对齐），等 P-001（基线层）
// 或 HG-023（规则层）命中，判定后必删。清理是进程内 os.Remove，不依赖
// 判断 ctx——即使窗口已超时也照常执行（与 Windows 版 cleanupWait 独立
// 预算同语义：演练不允许在目标机器留残留文件）。
func stepRegRun(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepRegRun, ExpectedRule: expectedRuleOf(StepRegRun)}
	if deps.AlertsSince == nil {
		return skip(StepRegRun, "AlertsSince 未接线")
	}
	if err := os.WriteFile(drillCronPath, []byte(drillCronBody), 0o644); err != nil {
		// 无 root 是常态：改在 /tmp 走一次写删，验证本步自身可运行；
		// 但 /tmp 不在持久化监控范围内，等价演练无法成立 → skipped。
		if tmpErr := os.WriteFile(drillCronTmp, []byte(drillCronBody), 0o644); tmpErr == nil {
			_ = os.Remove(drillCronTmp)
		}
		return skip(StepRegRun, "无权限写 /etc/cron.d（需要 root），已改在 /tmp/zedr-drill-cron 写删演练文件（该位置不触发持久化监控，本步跳过判定）")
	}
	defer func() {
		if err := os.Remove(drillCronPath); err != nil {
			deps.warn("drill_cleanup_failed", "what", "remove "+drillCronPath, "err", err.Error())
		}
	}()

	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "P-001", "HG-023")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "cron.d 写入已被捕获（" + strings.Join(hit.RuleIDs, ",") + "）；演练文件已删除"
	} else {
		res.Note = "30s 内未出现 P-001/HG-023 告警（P-001 走持久化层 5min 轮询，窗口内可能来不及枚举变更）"
	}
	return res
}

// stepCanaryTouch 勒索防御：删除一个探针自放的诱饵文件，等 FILE-CANARY
// 命中。诱饵由探针自检静默重建，演练不留缺口。
// 逻辑平台无关（读 deps.CanaryFile + 删除 + awaitHit），按平台文件对称
// 存放：两份实现必须保持一致（对齐 steps_windows.go 同名函数）。
func stepCanaryTouch(ctx context.Context, start time.Time, deps Deps) StepResult {
	res := StepResult{Name: StepCanaryTouch, ExpectedRule: "FILE-CANARY"}
	if deps.CanaryFile == nil {
		return skip(StepCanaryTouch, "CanaryFile 未接线")
	}
	if deps.AlertsSince == nil {
		return skip(StepCanaryTouch, "AlertsSince 未接线")
	}
	canary := deps.CanaryFile()
	if canary == "" {
		return skip(StepCanaryTouch, "未找到可用诱饵（HG_AGENT_FILE_DEFENSE 关闭或诱饵尚未放置）")
	}
	if err := os.Remove(canary); err != nil {
		res.Note = "删除诱饵失败: " + err.Error()
		return res
	}
	var hit AlertView
	hitAt, ok := awaitHit(ctx, func() bool {
		a, found := deps.alertHit(start, "FILE-CANARY")
		if found {
			hit = a
		}
		return found
	})
	res.Hit = ok
	res.LatencyMs = elapsedMs(start, hitAt, ok)
	res.AlertID = hit.ID
	if ok {
		res.Note = "诱饵删除已被勒索防御捕获；诱饵将由探针 30s 自检静默重建（" + redact.Path(canary) + "）"
	} else {
		res.Note = "30s 内未出现 FILE-CANARY 告警（USN/文件监控可能未覆盖诱饵目录）"
	}
	return res
}
