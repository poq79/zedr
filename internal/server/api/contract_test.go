package api

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"zedr/internal/server/domain"
)

// ---------------------------------------------------------------- 前端契约对拍（架构评审 P1-2 轻方案）
//
// webapp/src/lib/types.ts 的 interface 与服务端 DTO 的 json tag 是同一份
// 契约的两面——历史上至少漂移过一次（/me 缺 mfa_enabled，MFA 轮 E2E 才
// 发现）。本测试把核心 DTO 双向锁死：
//   正向：Go 侧每个非 "-" 的 json tag 必须出现在 TS interface 里
//   反向：TS 里非可选（无 ?）的字段必须存在于 Go tag
// TS 解析按 ";" 切字段（types.ts 是紧凑单行风格）。新增字段时本测试
// 会红——这是设计意图：契约变更必须两端同时改、显式提交。

type contractPair struct {
	tsName string
	goType reflect.Type
}

var contractPairs = []contractPair{
	{"Host", reflect.TypeOf(domain.Agent{})},
	{"Alert", reflect.TypeOf(domain.Alert{})},
	{"Rule", reflect.TypeOf(domain.Rule{})},
	{"Incident", reflect.TypeOf(domain.Incident{})},
	{"AgentCommand", reflect.TypeOf(domain.AgentCommand{})},
	{"IOC", reflect.TypeOf(domain.IOC{})},
	{"IntelItem", reflect.TypeOf(domain.IntelItem{})},
	{"HostInventorySection", reflect.TypeOf(domain.HostInventorySection{})},
}

var (
	ifaceHeadRe = regexp.MustCompile(`export interface (\w+) \{`)
	fieldRe     = regexp.MustCompile(`^\{?\s*(\w+)(\?)?\s*:`)
	goTagRe     = regexp.MustCompile(`json:"(\w+)[^"]*"`)
	exemptRe    = regexp.MustCompile(`json:"-"`)
)

// parseTSInterfaces 抽取 types.ts 里各 interface 的字段集（名 → 是否可选）。
// 三种形态都要接住：多行块、单行块（`export interface IOC { ... }`）、
// 块内注释（/* */ 与 //）——所以用括号平衡扫描而不是正则截取。
func parseTSInterfaces(t *testing.T, src string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, m := range ifaceHeadRe.FindAllStringSubmatchIndex(src, -1) {
		name := src[m[2]:m[3]]
		open := m[1] - 1 // 匹配串以 " {" 结尾，'{' 就在整体匹配末位
		depth := 0
		close := -1
		for i := open; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					close = i
				}
			}
			if close >= 0 {
				break
			}
		}
		if close < 0 {
			t.Fatalf("interface %s 的大括号不平衡（types.ts 语法异常）", name)
		}
		body := stripTSComments(src[open+1 : close])
		fields := map[string]bool{}
		for _, seg := range strings.Split(body, ";") {
			if fm := fieldRe.FindStringSubmatch(strings.TrimSpace(seg)); fm != nil {
				fields[fm[1]] = fm[2] == "?"
			}
		}
		out[name] = fields
	}
	return out
}

// stripTSComments 去掉块级与行注释（字段段里的注释会干扰 ; 切分后的
// 字段头识别）。
func stripTSComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		switch {
		case strings.HasPrefix(s[i:], "/*"):
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 4
		case strings.HasPrefix(s[i:], "//"):
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				return b.String()
			}
			i += end
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// goJSONTags 反射取结构体全部 json tag（跳过 "-"）。
func goJSONTags(typ reflect.Type) map[string]bool {
	tags := map[string]bool{}
	var walk func(typ reflect.Type)
	seen := map[reflect.Type]bool{}
	walk = func(typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			// Tag.Get 返回的是剥掉 "json:" 前缀的值（"id,omitempty"）——
			// 不要用 json:"..." 正则去匹配它（真坑，首版就栽在这）
			tag := f.Tag.Get("json")
			if tag == "" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "" || name == "-" {
				continue
			}
			tags[name] = true
			if f.Anonymous && (f.Type.Kind() == reflect.Struct || (f.Type.Kind() == reflect.Ptr && f.Type.Elem().Kind() == reflect.Struct)) {
				walk(f.Type)
			}
		}
	}
	walk(typ)
	return tags
}

func TestFrontendContract(t *testing.T) {
	src := readFile(t, locateTypesTS(t))
	tsIfaces := parseTSInterfaces(t, src)

	for _, p := range contractPairs {
		tsFields, ok := tsIfaces[p.tsName]
		if !ok {
			t.Errorf("types.ts 缺 interface %s（契约对拍清单引用了它）", p.tsName)
			continue
		}
		goTags := goJSONTags(p.goType)

		// 正向：Go 每个输出字段必须在 TS 里
		for tag := range goTags {
			if _, ok := tsFields[tag]; !ok {
				t.Errorf("[正向漂移] %s.Go 字段 %q (json tag) 不在 TS interface %s 中——前端拿不到该字段，需要同步 types.ts",
					p.goType.String(), tag, p.tsName)
			}
		}
		// 反向：TS 非可选字段必须在 Go tag 里（TS 必填 = 前端逻辑依赖它恒存在）
		for f, optional := range tsFields {
			if optional {
				continue
			}
			if !goTags[f] {
				t.Errorf("[反向漂移] %s.TS 必填字段 %q 不在 Go struct %s 的 json tag 中——服务端可能不发该字段",
					p.tsName, f, p.goType.String())
			}
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读契约文件失败: %v", err)
	}
	return string(b)
}

// locateTypesTS 从 cwd 逐级向上找 webapp/src/lib/types.ts——go test 的
// cwd 是包目录（internal/server/api），编译后手动执行是仓根，两种口径
// 都兼容；找不到直接 Fatal（契约文件缺失 = 仓库不完整）。
func locateTypesTS(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join("webapp", "src", "lib", "types.ts")
	for i := 0; i < 6; i++ {
		cand := filepath.Join(dir, rel)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("未找到 webapp/src/lib/types.ts（从 %s 向上探测）", dir)
	return ""
}
