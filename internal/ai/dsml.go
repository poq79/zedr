package ai

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// DSML 泄漏的恢复层（2026-11-19，形态实测见 agent.go sanitizeDSML 注释）。
//
// 调研结论（2026-11-19，来源见 overview.md）：这是 DeepSeek v4.1 系模型
// 的已知行为——工具调用偶发以 DSML 特殊 token 文本写进 content 通道；
// vLLM 为其内置了专门的 deepseek_v41 tool parser，社区（opencode
// dsml-fix 等插件）走同一条"恢复成结构化 tool call"的路。标准前端组件
// 不解决此问题（它们假设传输层已产出结构化 part），解法全在引擎/流式层。

var (
	// dsmlInvokeRe 匹配一次 invoke 块（name + 参数区）；
	// 管道字符 ASCII | 与全角 ｜ 混排，字符类通吃。
	dsmlInvokeRe = regexp.MustCompile(`(?s)<[|｜ ]*DSML[|｜ ]*invoke name="([^"]+)">(.*?)<[|｜ ]*DSML[|｜ ]*invoke>`)
	// dsmlParamRe 匹配块内一个参数（string="true" 表示值是字符串，
	// "false" 表示值是数字/布尔等原始类型——按 DeepSeek 标记约定）。
	dsmlParamRe = regexp.MustCompile(`(?s)<[|｜ ]*DSML[|｜ ]*parameter name="([^"]+)"[^>]*>(.*?)<[|｜ ]*DSML[|｜ ]*parameter>`)
)

// parseDSMLCalls 从泄漏文本里恢复结构化工具调用；恢复不了返回 nil
// （残损块由 sanitizeDSML 做 redact，不回显）。
func parseDSMLCalls(content string) []ToolCall {
	if !strings.Contains(content, "DSML") {
		return nil
	}
	var out []ToolCall
	for i, m := range dsmlInvokeRe.FindAllStringSubmatch(content, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" {
			continue
		}
		args := map[string]any{}
		for _, pm := range dsmlParamRe.FindAllStringSubmatch(m[2], -1) {
			key := strings.TrimSpace(pm[1])
			val := strings.TrimSpace(pm[2])
			if key == "" {
				continue
			}
			// string="false" 的值是数字/布尔：能解析就还原类型，
			// 解析不了当字符串（与工具参数校验的容错口径一致）
			if !strings.Contains(strings.ToLower(pm[0]), `string="true"`) {
				var v any
				if json.Unmarshal([]byte(val), &v) == nil {
					args[key] = v
					continue
				}
			}
			args[key] = val
		}
		raw, err := json.Marshal(args)
		if err != nil {
			raw = []byte("{}")
		}
		out = append(out, ToolCall{
			ID:        fmt.Sprintf("dsml-%s-%d", name, i),
			Name:      name,
			Arguments: string(raw),
		})
	}
	return out
}
