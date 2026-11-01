package service

import (
	"context"
	"fmt"
	"strings"
)

// Hunt v2：多轮会话式狩猎。
//
// 设计口径：
//   - LLM 引擎下，把前几轮"问题 → 当时理解"作为背景带给翻译器，
//     支持"这些结果里只要未签名的"这类基于上文结果的追问；
//   - 确定性引擎只解析当前句——关键词解析器看到历史里的
//     "powershell" 之类的词会把旧条件串进新查询，反而更糟，
//     宁可少理解也不误理解（诚实降级）。
//
// 历史由前端保存并随请求携带（服务端不存会话状态）：无状态、
// 多实例友好，也避免"会话"变成新的持久化面。

// HuntTurn 是一轮历史检索。
type HuntTurn struct {
	Query   string `json:"query"`
	Explain string `json:"explain,omitempty"`
}

// huntHistoryCap 是带给翻译器的历史上限：更多轮次的边际价值很低，
// 却会让提示词线性膨胀、稀释当前追问。
const huntHistoryCap = 5

// HuntConversation 带历史上下文的检索。
func (s *AIService) HuntConversation(ctx context.Context, nl string, history []HuntTurn) (*HuntResult, error) {
	if len(history) == 0 {
		return s.Hunt(ctx, nl)
	}
	// 确定性引擎不做历史拼接（见文件头注释）
	if s.eng.Stats().Engine != "llm" {
		return s.Hunt(ctx, nl)
	}

	var b strings.Builder
	b.WriteString("此前的检索（背景信息；只有当当前追问明确引用上文时才延续其中的条件，否则以当前追问为准）:\n")
	start := 0
	if len(history) > huntHistoryCap {
		start = len(history) - huntHistoryCap
	}
	for _, h := range history[start:] {
		q := strings.TrimSpace(h.Query)
		if q == "" {
			continue
		}
		ex := strings.TrimSpace(h.Explain)
		if ex == "" {
			ex = "（未记录理解）"
		}
		fmt.Fprintf(&b, "- 问题: %s；当时的理解: %s\n", q, ex)
	}
	fmt.Fprintf(&b, "\n当前追问: %s", nl)

	res, err := s.Hunt(ctx, b.String())
	if err != nil {
		return nil, err
	}
	// Explain 里保留的是"整段上下文"的翻译说明；为了前端可读，
	// 在解释前标注"基于上文"，避免分析师误以为是纯当前句的解析。
	if res.Query != nil {
		res.Query.Explain = "（基于上文）" + res.Query.Explain
	}
	return res, nil
}
