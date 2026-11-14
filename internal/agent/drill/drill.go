// Package drill 检测演练（Detection Drill）执行器。
//
// 目的：私有化交付验收与升级后回归——管理员在服务端对一台主机发起演练，
// 探针本地执行受控自测（全部自造样本：echo+回环 ping、TEST-NET SYN、
// demand 空服务、Run 键写删、删自家诱饵），让各检测层真实触发，
// 结果随指令回执回传。全程零真实恶意样本、零真实外联。
//
// 设计约束：
//   - 本包不 import agentapp（组合根与执行器互相依赖会锁死测试）；
//     依赖全部经 Deps 注入，由 agentapp 在指令分发处接线。
//   - 步骤同步执行，总预算 150s 硬顶：handleCommands 是同步回执模型，
//     演练期间心跳顺延，150s 远小于服务端侧任何超时判定。
//   - 判定口径是"期望规则出现在本步骤开始之后的新告警里"——只看增量，
//     不碰历史告警，避免上一次演练或真实攻击的残留命中造成假阳性。
//   - 前置不满足（采集开关关、无诱饵）记 skipped 而不是失败：
//     演练报告要回答"测了什么、结果如何"，"没测"和"没测出来"必须可区分。
package drill

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// 步骤名（服务端白名单同名单，见 internal/server/api/drill.go 注释）。
const (
	StepProcChain   = "proc_chain"    // 采集管线健康检查：新进程可见
	StepPortScan    = "port_scan"     // 网络行为检测 NW-001/NW-004
	StepServiceEvt  = "service_event" // 事件日志层 E1：服务安装事件 EVT-SVCINST
	StepRegRun      = "reg_run"       // 持久化检测：P-001（基线层）/ HG-023（规则层）
	StepCanaryTouch = "canary_touch"  // 勒索防御：诱饵删除 FILE-CANARY
)

// PipelineSentinel 是 proc_chain 的 expected_rule 占位：该步骤验证的是
// 采集管线本身（新进程出现在进程表），不对应任何规则 ID。
const PipelineSentinel = "__pipeline__"

// 预算与节奏。
const (
	// TotalBudget 是整场演练的硬顶。五步窗口之和（220s）刻意超出它：
	// 命中通常远早于窗口上限；真超预算时剩余步骤记 skipped，
	// 演练不允许无限占用同步回执链路。
	TotalBudget = 150 * time.Second

	// syncWait 是 sc/reg 这类同步子命令的执行上限。
	syncWait = 15 * time.Second

	// cleanupWait 是清理动作（sc delete / reg delete）的独立预算：
	// 判断窗口的 ctx 可能已超时，清理必须用新鲜预算，否则半途而废的
	// 演练会在目标机器上留下残留服务/注册表值——那比演练失败更糟。
	cleanupWait = 15 * time.Second
)

// pollEvery 与进程扫描节奏（2s）对齐：轮询再密也只是空转。
// var 而非 const 仅为一件事：单测可缩短节奏验证命中/超时判定，生产代码不写它。
var pollEvery = 2 * time.Second

// stepBudget 各步骤的独立判定窗口。
func stepBudget(name string) time.Duration {
	switch name {
	case StepProcChain:
		return 10 * time.Second
	case StepPortScan:
		return 60 * time.Second
	case StepServiceEvt:
		// 90s：E1 事件日志层是 30s/tick 游标轮询，探针重启后的首批
		// 读取还可能带历史回放（2026-11-14 E2E 实测：7045 在步骤起点
		// 后 ~68s 才随回放批次到达，60s 窗口错过但事件真实被捕获）。
		return 90 * time.Second
	case StepRegRun, StepCanaryTouch:
		return 30 * time.Second
	}
	return 10 * time.Second
}

// ---------------------------------------------------------------- 数据模型

// StepResult 是单步演练结果（随 CommandResult.Result 回传，服务端按同
// 形状解析成结构化步骤结果）。
type StepResult struct {
	Name         string `json:"name"`
	ExpectedRule string `json:"expected_rule"`
	Hit          bool   `json:"hit"`
	LatencyMs    int64  `json:"latency_ms"`
	AlertID      string `json:"alert_id,omitempty"`
	Note         string `json:"note,omitempty"`

	// skipped 标记"前置不满足未执行"（Note 以 "skipped: " 开头说明原因）。
	// 不进 JSON：外层 Report.Skipped 已承载名单，重复字段徒增回执体积
	// （服务端对回执有长度钳制，能省则省）。
	skipped bool
}

// AlertView 是判定所需的告警投影（agentapp 从 state.Store.Alerts 映射）。
type AlertView struct {
	ID         string
	RuleIDs    []string
	OccurredAt time.Time
}

// ProcView 是判定所需的进程投影（agentapp 从 state.Store.Procs 映射）。
type ProcView struct {
	PID  uint32
	Name string
}

// Deps 是执行器依赖（agentapp 接线注入；nil 字段对应步骤记 skipped）。
type Deps struct {
	// AlertsSince 返回 OccurredAt 不早于 t 的本地告警。
	AlertsSince func(t time.Time) []AlertView
	// ProcSnapshot 返回当前进程表快照（采集管线产物）。
	ProcSnapshot func() []ProcView
	// CanaryFile 返回一个存在的诱饵文件路径；空串 = 无可用诱饵
	// （勒索防御关闭或诱饵尚未放置）。
	CanaryFile func() string
	// EvtLogEnabled 对应 HG_AGENT_EVTLOG（E1 事件日志接入）。
	EvtLogEnabled bool
	// NetWatchEnabled 对应 HG_AGENT_NETWATCH（NW-001~005）。
	NetWatchEnabled bool
	Log             *slog.Logger
	SelfPID         uint32
}

// Report 是整场演练报告（写入 CommandResult.Result 的 JSON 结构）。
type Report struct {
	Steps   []StepResult `json:"steps"`
	Skipped []string     `json:"skipped,omitempty"`
}

// ---------------------------------------------------------------- 白名单与 payload

// AllSteps 返回全部步骤名（固定执行顺序：先查采集管线，再查网络/事件/
// 持久化层，最后查文件层）。
func AllSteps() []string {
	return []string{StepProcChain, StepPortScan, StepServiceEvt, StepRegRun, StepCanaryTouch}
}

// IsValidStep 白名单判定。
func IsValidStep(name string) bool {
	for _, s := range AllSteps() {
		if s == name {
			return true
		}
	}
	return false
}

// ParsePayload 解析指令 payload（{"steps":[...]}）。空 payload / 空数组 = 全跑。
// 服务端已做过白名单校验，这里再校验一次：指令链路上服务端只是第一道门，
// 探针不能假设上游永远正确（老服务端/手工造的指令都可能带脏步骤名）。
func ParsePayload(raw string) ([]string, error) {
	var p struct {
		Steps []string `json:"steps"`
	}
	if s := strings.TrimSpace(raw); s != "" {
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			return nil, fmt.Errorf("payload 不是合法 JSON: %w", err)
		}
	}
	if len(p.Steps) == 0 {
		return AllSteps(), nil
	}
	seen := make(map[string]struct{}, len(p.Steps))
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		s = strings.TrimSpace(s)
		if !IsValidStep(s) {
			return nil, fmt.Errorf("未知步骤 %q（可用: %s）", s, strings.Join(AllSteps(), ", "))
		}
		if _, dup := seen[s]; dup {
			continue // 重复步骤重跑没有信息增量，只会拉长总耗时
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

// BuildReport 汇总演练报告（收集被跳过的步骤名）。
func BuildReport(steps []StepResult) Report {
	r := Report{Steps: steps}
	for _, s := range steps {
		if s.skipped {
			r.Skipped = append(r.Skipped, s.Name)
		}
	}
	return r
}

// MarshalReport 序列化报告（写入 CommandResult.Result）。
func MarshalReport(r Report) string {
	b, err := json.Marshal(r)
	if err != nil {
		return "" // 仅基本类型字段，实际不可达；回执空串好过半截 JSON
	}
	return string(b)
}

// ---------------------------------------------------------------- 执行

// Run 顺序执行步骤并返回逐步结果。steps 为空时全跑。
func Run(ctx context.Context, steps []string, deps Deps) []StepResult {
	if len(steps) == 0 {
		steps = AllSteps()
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	total, cancel := context.WithTimeout(ctx, TotalBudget)
	defer cancel()

	out := make([]StepResult, 0, len(steps))
	for _, name := range steps {
		if total.Err() != nil {
			out = append(out, skip(name, "演练总预算（150s）已耗尽，本步未执行"))
			continue
		}
		res := runStep(total, name, deps)
		deps.Log.Info("drill_step", "step", name, "hit", res.Hit,
			"latency_ms", res.LatencyMs, "note", res.Note)
		out = append(out, res)
	}
	return out
}

func runStep(parent context.Context, name string, deps Deps) StepResult {
	ctx, cancel := context.WithTimeout(parent, stepBudget(name))
	defer cancel()
	start := time.Now()
	switch name {
	case StepProcChain:
		return stepProcChain(ctx, start, deps)
	case StepPortScan:
		return stepPortScan(ctx, start, deps)
	case StepServiceEvt:
		return stepServiceEvt(ctx, start, deps)
	case StepRegRun:
		return stepRegRun(ctx, start, deps)
	case StepCanaryTouch:
		return stepCanaryTouch(ctx, start, deps)
	default:
		return skip(name, "未知步骤（本探针版本不支持）")
	}
}

// skip 构造"前置不满足"结果：Hit=false + skipped 标记，不算失败——
// 报告要能区分"没测"与"测了没中"。
func skip(name, why string) StepResult {
	return StepResult{Name: name, ExpectedRule: expectedRuleOf(name), Note: "skipped: " + why, skipped: true}
}

func expectedRuleOf(name string) string {
	switch name {
	case StepProcChain:
		return PipelineSentinel
	case StepPortScan:
		return "NW-001/NW-004"
	case StepServiceEvt:
		return "EVT-SVCINST"
	case StepRegRun:
		// P-001（持久化基线层）与 HG-023（规则层）是同一条 T1547.001 的两条
		// 检测路径：regwatch 开启时 P-001 秒级，否则等 5min 轮询；
		// HG-023 在进程扫描（2s）内必现。命中任一即算该步通过。
		return "P-001/HG-023"
	case StepCanaryTouch:
		return "FILE-CANARY"
	}
	return ""
}

// ---------------------------------------------------------------- 步骤实现

// 五个步骤的平台实现按构建标签拆分：
//   - steps_windows.go：cmd/powershell/sc/reg 全走系统自带工具；
//   - steps_linux.go：Go 原生拨号 + 进程内文件写删，无等价信号源的步骤
//     （服务安装事件）诚实记 skipped。
// 两平台各自提供 runStep 所需的同名函数；本文件只保留调度、判定与报告。

// ---------------------------------------------------------------- 依赖与轮询原语

// alertHit 在"步骤开始之后"的新告警里找期望规则。
func (d Deps) alertHit(since time.Time, rules ...string) (AlertView, bool) {
	if d.AlertsSince == nil {
		return AlertView{}, false
	}
	for _, a := range d.AlertsSince(since) {
		for _, got := range a.RuleIDs {
			for _, want := range rules {
				if got == want {
					return a, true
				}
			}
		}
	}
	return AlertView{}, false
}

// awaitHit 每 2s 轮询一次 found，命中立即返回；ctx 到期判未命中。
// 先查一次再进 tick：判定动作本身可能已完成（采集是异步流水线）。
func awaitHit(ctx context.Context, found func() bool) (time.Time, bool) {
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	if found() {
		return time.Now(), true
	}
	for {
		select {
		case <-ctx.Done():
			return time.Time{}, false
		case <-ticker.C:
			if found() {
				return time.Now(), true
			}
		}
	}
}

// warn 空安全的日志（步骤可被单测直接驱动，Deps.Log 可能缺省）。
func (d Deps) warn(msg string, kv ...any) {
	if d.Log != nil {
		d.Log.Warn(msg, kv...)
	}
}

func elapsedMs(start, hitAt time.Time, hit bool) int64 {
	if hit {
		return hitAt.Sub(start).Milliseconds()
	}
	return time.Since(start).Milliseconds()
}
