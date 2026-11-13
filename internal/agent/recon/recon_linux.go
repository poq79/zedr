//go:build linux

package recon

// recon_linux.go — 入口与编排，Linux 版。与 recon.go（Windows 版）等价
// 实现：六类 detector 并发执行，共用一份基础关联数据与一个探测预算闸；
// 整体 30s 预算到点返回已收集部分（truncated=true）。
//
// 为什么独立成文件而不是抽共享：Windows 版的 Deps.Netstat 绑定
// winapi.NetRow（类型别名到 nettypes.NetRow，语义相同），且 recon.go/
// base.go 不在本次 Linux 移植的所有权范围内。**两份编排必须同步演进**
// ——改 Run/ParseCategories 的行为时必须同时检查对面文件。
//
// 输出结构体（Result/Category/AssetItem/…）在 types.go，双平台共享
// 同一形状——服务端消费零分叉，这是移植的硬约束。
//
// 未在 Linux 实机验证（本机无 Linux 测试环境）；验证口径 = GOOS=linux
// 交叉编译 + linuxparse.go 纯逻辑单测。

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/nettypes"
	"zedr/internal/agent/state"
)

const (
	// runBudget 是整体预算（契约 §12.1）。探针侧先到点就先返回，
	// 中心代理给 40s 是为了让 truncated 语义有机会送达。
	runBudget = 30 * time.Second

	// maxProbeRequests 是单次侦查的总探测上限（契约 §12.4）。
	// 按请求计数而不是按资产计数：一个产品可能根页 + 能力端点各一次。
	maxProbeRequests = 40

	// probeTimeout 是单次探测超时（契约 §12.4）。
	probeTimeout = 2 * time.Second

	// probeBodyLimit 是单次响应读取上限（契约 §12.4）。
	probeBodyLimit = 64 << 10
)

// Deps 是 recon.Run 的全部外部依赖（由组合根从 state/collect 适配，
// 与 Windows 版 liveapi 薄 handler 的适配方式同构）。
//
// 全部为函数/值字段，无锁无原子，按值传递安全。
type Deps struct {
	// Procs 返回实时进程快照（通常包一层 state.Store.Procs(2000)）。
	Procs func() []state.ProcRow
	// Netstat 返回带 PID 的连接表（/proc/net + inode→PID 反查投影，
	// nettypes.NetRow 与 Windows 的 winapi.NetRow 同形状——单一事实源）。
	Netstat func() []nettypes.NetRow
	// Probe=false 时走纯被动模式：不发起任何网络请求。
	Probe bool
	// Now 是时钟注入点（单测固定 generated_at）；nil 用 time.Now。
	Now func() time.Time
}

// detectorFunc 是单类 detector 的签名。返回的 Category 必须带 Key/Title；
// error 表示该类整体失败（Run 会转成类目级说明，不影响其他类）。
type detectorFunc func(context.Context, *base) (Category, error)

// detectorTable 把类目 key 映射到实现。web/ai/db/dev/virt 六类里的五个
// 是双平台共享实现（web.go/ai.go/db.go/dev.go/virt.go 无构建标签）；
// remote 是 Windows/Linux 各自实现（RDP 注册表面 vs SSH/sshd 配置面）。
var detectorTable = map[string]detectorFunc{
	"web": detectWeb,
	// ai：detectAIFace = detectAI（既有 harness 识别）+ agent_face 端侧
	// AI 面清点（agentface.go），六类稳定面不变。
	"ai":     detectAIFace,
	"db":     detectDB,
	"remote": detectRemote,
	"dev":    detectDev,
	"virt":   detectVirt,
}

// ParseCategories 解析 categories 参数：
//   - 空串 = 全部六类；
//   - 逗号分隔，大小写不敏感，允许空白；
//   - 未知类目返回错误（handler 统一转 400），重复项去重保序。
func ParseCategories(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Categories(), nil
	}
	valid := make(map[string]struct{}, len(categoryOrder))
	for _, c := range categoryOrder {
		valid[c.Key] = struct{}{}
	}
	seen := make(map[string]struct{}, len(categoryOrder))
	out := make([]string, 0, len(categoryOrder))
	for _, part := range strings.Split(raw, ",") {
		key := strings.ToLower(strings.TrimSpace(part))
		if key == "" {
			return nil, fmt.Errorf("categories 含空项")
		}
		if _, ok := valid[key]; !ok {
			return nil, fmt.Errorf("未知资产分类 %q（可选：%s）", key, strings.Join(Categories(), ","))
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("categories 不能为空")
	}
	return out, nil
}

// Run 执行资产侦查。categories 为空 = 全部；未知类目返回错误。
//
// 六类并发而不是串行：主动探测单次 2s、总预算 30s，串行时 40 次探测
// 最坏 80s 必然超时；并发还能让"某一类卡住"只损失该类。
func Run(ctx context.Context, d Deps, cats []string) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	now := d.Now
	if now == nil {
		now = time.Now
	}
	if len(cats) == 0 {
		cats = Categories()
	}
	// 直接调用 Run 的测试/内部调用也要走同一套校验，不能只依赖 handler。
	cats, err := normalizeCategories(cats)
	if err != nil {
		return Result{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, runBudget)
	defer cancel()

	b := newBase(d)

	type outcome struct {
		idx int
		cat Category
	}
	ch := make(chan outcome, len(cats))
	for i, key := range cats {
		fn := detectorTable[key]
		if fn == nil {
			// normalizeCategories 已保证 key 合法；这里防御表被改坏。
			ch <- outcome{idx: i, cat: errorCategory(key, "detector 未实现")}
			continue
		}
		go func(i int, key string, fn detectorFunc) {
			cat := runDetector(runCtx, key, fn, b)
			ch <- outcome{idx: i, cat: cat}
		}(i, key, fn)
	}

	results := make([]Category, len(cats))
	got := make([]bool, len(cats))
	remaining := len(cats)
	truncated := false
	for remaining > 0 {
		select {
		case o := <-ch:
			if !got[o.idx] {
				results[o.idx] = o.cat
				got[o.idx] = true
				remaining--
			}
		case <-runCtx.Done():
			// 预算到点：不等待卡住的 detector；已发出的结果在 ch 里，
			// 未收到的类目用类目级说明占位。goroutine 不会因此泄漏——
			// ch 有 len(cats) 缓冲，runCtx 取消后探测/文件读取都会退出。
			truncated = true
			remaining = 0
		}
	}
	if runCtx.Err() != nil {
		truncated = true
	}
	for i := range results {
		if !got[i] {
			results[i] = errorCategory(cats[i], "侦查未在 30s 预算内完成，结果可能不完整")
		}
	}

	res := Result{
		GeneratedAt: now().UTC().Format(time.RFC3339),
		DurationMS:  time.Since(start).Milliseconds(),
		Probed:      d.Probe,
		Truncated:   truncated,
		Categories:  results,
	}
	return res, nil
}

// normalizeCategories 校验并去重（保留调用方顺序）；空 = 全部。
func normalizeCategories(in []string) ([]string, error) {
	if len(in) == 0 {
		return Categories(), nil
	}
	valid := make(map[string]struct{}, len(categoryOrder))
	for _, c := range categoryOrder {
		valid[c.Key] = struct{}{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		key := strings.ToLower(strings.TrimSpace(raw))
		if _, ok := valid[key]; !ok {
			return nil, fmt.Errorf("未知资产分类 %q", raw)
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, nil
}

// runDetector 执行单类 detector 并把 panic/error 收口为类目级说明。
// 这是"单类失败不影响其他类"的最后一道保险：detector 内部处理不了的
// 意外（空指针、第三方 API 变更）不能拆掉整次侦查。
func runDetector(ctx context.Context, key string, fn detectorFunc, b *base) (cat Category) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Warn("recon_detector_panic", "category", key, "panic", fmt.Sprint(rec))
			cat = errorCategory(key, fmt.Sprintf("detector panic: %v", rec))
		}
	}()
	cat, err := fn(ctx, b)
	if cat.Key == "" {
		cat = newCategory(key, CategoryTitle(key))
	}
	if err != nil {
		slog.Warn("recon_detector_failed", "category", key, "err", err)
		cat.Error = err.Error()
		cat.Findings = append(cat.Findings, Finding{
			Level:  LevelInfo,
			Title:  CategoryTitle(key) + " 侦查部分失败",
			Detail: err.Error(),
		})
	}
	return cat
}

// sortItems 按暴露等级降序、标题升序稳定排序，让前端"先看最危险的"。
func sortItems(items []AssetItem) {
	rank := map[string]int{
		LevelCritical: 5,
		LevelHigh:     4,
		LevelMedium:   3,
		LevelLow:      2,
		LevelInfo:     1,
		LevelUnknown:  0,
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := rank[items[i].Exposure.Level], rank[items[j].Exposure.Level]
		if ri != rj {
			return ri > rj
		}
		return items[i].Title < items[j].Title
	})
}
