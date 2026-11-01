package recon

// parse.go：探测响应的轻量解析（不引入 HTML/JSON 之外的新依赖）。
// 所有函数只用于"指纹识别"，不追求完整 HTML/JSON 语义；解析失败
// 一律返回零值，让调用方按 unknown 降级。

import (
	"bytes"
	"encoding/json"
	"html"
	"regexp"
	"strings"
)

var (
	reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// 登录页特征：password 输入框是最硬的信号；login 表单/标题次之。
	rePasswordInput = regexp.MustCompile(`(?is)<input[^>]+type\s*=\s*["']?password`)
	reLoginForm     = regexp.MustCompile(`(?is)<form[^>]+(?:login|signin|sign-in|auth)`)
)

// htmlTitle 提取 <title> 文本并折叠空白；无标题返回空串。
func htmlTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := html.UnescapeString(string(m[1]))
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// looksLikeLoginPage 判定 200 根页是否是登录页。
// 只看 password 输入框、login 表单、标题登录词三类硬信号；
// 正文里出现 "login" 链接不算（大量营销页/文档页都有）。
func looksLikeLoginPage(body []byte, title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	if strings.Contains(t, "login") || strings.Contains(t, "sign in") || strings.Contains(t, "登录") {
		return true
	}
	if rePasswordInput.Match(body) {
		return true
	}
	if reLoginForm.Match(body) {
		return true
	}
	return false
}

// jsonHasKey 判断响应是否是 JSON 对象且包含指定顶层 key。
// 只做顶层判断：产品能力端点的数据形状都在顶层（models/data/version）。
func jsonHasKey(body []byte, key string) bool {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// jsonString 取顶层字符串字段（version 等）；缺失/类型不符返回空串。
func jsonString(body []byte, key string) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// jsonNestedString 取 obj.key1.key2 形式的嵌套字符串（ES version.number）。
func jsonNestedString(body []byte, k1, k2 string) string {
	var m map[string]map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	inner, ok := m[k1]
	if !ok {
		return ""
	}
	if v, ok := inner[k2].(string); ok {
		return v
	}
	return ""
}
