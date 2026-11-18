package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// 今日值班简报的 AI 态势叙述段（2026-11-11 主动式 AI 轮的收尾）。
//
// 为什么不用 NarrateIncident：那是事件级攻击链叙事，输入是告警集合；
// 简报的输入是统计数字。两者共享 narrative 槽位（可单独配强模型），
// 但提示词纪律完全不同——简报的纪律是"数字是唯一事实源"。

// briefingEntry 是简报叙述的短时缓存：总览页每次打开都拉简报，
// 没有缓存的话每 30 分钟窗口也会被反复打开烧穿。
type briefingEntry struct {
	text string
	at   time.Time
}

var (
	briefCacheMu sync.Mutex
	briefCache   = map[string]briefingEntry{}
)

// briefCacheTTL 与研判缓存默认值同口径；简报是聚合数字，半小时内
// 重复打开本来就看不到变化。
const briefCacheTTL = 30 * time.Minute

func briefCacheKey(statsText string) string {
	sum := sha256.Sum256([]byte(statsText))
	return hex.EncodeToString(sum[:8])
}

// BriefNarrative 生成值班简报的 AI 态势叙述（2-4 句中文）。
// 返回 (text, state)：state 为 "ai"（成功）或降级原因（text 为空）。
// 纪律：只引用给出的统计数字，禁止外部知识——简报必须可核对，
// "看起来聪明但不可核对"比不聪明更糟。
func (e *Engine) BriefNarrative(ctx context.Context, statsText string) (string, string) {
	key := briefCacheKey(statsText)
	briefCacheMu.Lock()
	if hit, ok := briefCache[key]; ok && time.Since(hit.at) < briefCacheTTL {
		briefCacheMu.Unlock()
		return hit.text, "ai"
	}
	briefCacheMu.Unlock()

	be := e.backend(SlotNarrative)
	if be == nil {
		return "", "未配置外部模型"
	}
	if e.budgetLeft() <= 0 {
		return "", "本小时 token 预算已用尽"
	}
	ob, ok := be.(*OpenAICompatible)
	if !ok {
		return "", "当前后端不支持文本生成"
	}
	sys := strings.Join([]string{
		"你是安全运营值班助手。基于给出的值班统计写一段 2-4 句的中文态势叙述，供值班人员开屏即读。",
		"纪律：",
		"1. 只能引用给出的数字与事实，禁止任何外部知识、推测或建议性的处置动作；",
		"2. 先给一句总体判断，再点出最值得注意的 1-2 个数字及其含义；",
		"3. 数字为零或很小的项不提，不要逐项复述；",
		"4. 不输出标题、列表符号、markdown 或客套话。",
	}, "\n")
	text, _, err := // maxTokens 放宽：deepseek v4.1 是 reasoning 模型，思考链先于正文消耗
	// token——预算太小时正文为空（2026-11-19 实测 400 不够，1200 稳定）
	ob.chatText(ctx, sys, statsText, 1200)
	if err != nil {
		return "", "模型调用失败：" + err.Error()
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return "", "模型未给出叙述"
	}

	briefCacheMu.Lock()
	if len(briefCache) > 64 {
		briefCache = map[string]briefingEntry{}
	}
	briefCache[key] = briefingEntry{text: text, at: time.Now()}
	briefCacheMu.Unlock()
	return text, "ai"
}
