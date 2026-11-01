// Package rules 实现 Sigma 风格的行为规则 DSL、求值器与内置规则集。
//
// 一条规则由若干条件组成：
//
//	{"all":[{"field":"process.name","op":"in","value":["winword.exe"]}],
//	 "any":[{"field":"process.cmdline","op":"icontains","value":"-enc"}],
//	 "none":[...]}
//
// all 全部成立、any 至少一条成立、none 全部不成立 → 命中。
// 规则与 TCP 无关、与 HTTP 无关，可被探针本地求值，也可被服务端做干跑校验。
package rules

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Condition 是一条原子判定。
type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

// Definition 是一条规则的完整条件体。
type Definition struct {
	All  []Condition `json:"all,omitempty"`
	Any  []Condition `json:"any,omitempty"`
	None []Condition `json:"none,omitempty"`
}

// Target 是被检测进程的字段快照，供条件求值使用。
type Target struct {
	Name        string   // 进程名（含 .exe）
	Path        string   // 完整路径
	CmdLine     string   // 完整命令行
	User        string   // 运行账号
	ParentName  string   // 父进程名
	ParentPath  string   // 父进程路径
	Ancestors   []string // 祖先链进程名（由近到远）
	Signed      bool     // 是否有可信数字签名
	SignatureOK bool     // 签名链是否校验通过
	Signer      string   // 签名主体
	Elevated    bool     // 是否高完整性（管理员）
	InSystem      bool   // 是否位于 System32/SysWOW64/WinSxS
	DirWritable   bool   // 镜像所在目录是否用户可写
	SessionID     uint32 // 会话 ID（0=系统会话）
	NetConnCount  int    // 活跃网络连接数
	RemotePorts   []uint32
	HasPublicRemote bool // 是否存在非内网远端
	UnsignedModules int  // 加载的未签名模块数
	NonSystemModules int // 从非系统目录加载的模块数
	FilePathDepth   int  // 路径层级（用于识别深层伪装目录）
}

// Eval 编译后的规则。
type Eval struct {
	ID         string
	Name       string
	Severity   string
	Score      int
	MITRE      []string
	Definition Definition
}

// Compile 解析规则定义 JSON。
func Compile(defJSON string) (*Definition, error) {
	var d Definition
	if err := json.Unmarshal([]byte(defJSON), &d); err != nil {
		return nil, fmt.Errorf("规则定义 JSON 解析失败: %w", err)
	}
	if len(d.All) == 0 && len(d.Any) == 0 && len(d.None) == 0 {
		return nil, fmt.Errorf("规则定义至少要包含 all / any / none 之一")
	}
	for _, group := range [][]Condition{d.All, d.Any, d.None} {
		for _, c := range group {
			if c.Field == "" || c.Op == "" {
				return nil, fmt.Errorf("条件缺少 field 或 op")
			}
		}
	}
	return &d, nil
}

var regexCache sync.Map // pattern -> *regexp.Regexp

func compileRegex(p string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(p); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	regexCache.Store(p, re)
	return re, nil
}

// Match 对目标求值，返回是否命中以及命中的条件描述（用于证据展示）。
func (d *Definition) Match(t *Target) (bool, []string) {
	var hits []string

	for _, c := range d.All {
		ok, desc := evalCond(c, t)
		if !ok {
			return false, nil
		}
		hits = append(hits, desc)
	}

	if len(d.Any) > 0 {
		anyHit := false
		for _, c := range d.Any {
			ok, desc := evalCond(c, t)
			if ok {
				anyHit = true
				hits = append(hits, desc)
			}
		}
		if !anyHit {
			return false, nil
		}
	}

	for _, c := range d.None {
		ok, _ := evalCond(c, t)
		if ok {
			return false, nil
		}
	}

	return true, hits
}

// fieldValue 把字段名映射到实际值。
func fieldValue(field string, t *Target) (any, bool) {
	switch field {
	// 进程
	case "process.name", "proc.name":
		return t.Name, true
	case "process.path", "proc.path":
		return t.Path, true
	case "process.cmdline", "proc.cmdline":
		return t.CmdLine, true
	case "process.user", "proc.user":
		return t.User, true
	case "process.signed":
		return t.Signed, true
	case "process.signature_ok":
		return t.SignatureOK, true
	case "process.signer":
		return t.Signer, true
	case "process.elevated":
		return t.Elevated, true
	case "process.in_system":
		return t.InSystem, true
	case "process.dir_writable":
		return t.DirWritable, true
	case "process.session":
		return int(t.SessionID), true
	case "process.depth":
		return t.FilePathDepth, true
	// 血缘
	case "parent.name":
		return t.ParentName, true
	case "parent.path":
		return t.ParentPath, true
	case "ancestor.names":
		return t.Ancestors, true
	// 网络
	case "network.count":
		return t.NetConnCount, true
	case "network.remote_ports":
		return t.RemotePorts, true
	case "network.has_public_remote":
		return t.HasPublicRemote, true
	// 模块
	case "module.unsigned_count":
		return t.UnsignedModules, true
	case "module.non_system_count":
		return t.NonSystemModules, true
	}
	return nil, false
}

func evalCond(c Condition, t *Target) (bool, string) {
	v, ok := fieldValue(c.Field, t)
	if !ok {
		return false, ""
	}

	desc := func() string {
		return c.Field + " " + c.Op + " " + stringify(c.Value)
	}

	switch c.Op {
	case "exists":
		return true, desc()
	case "eq":
		return compareScalar(v, c.Value) == 0, desc()
	case "ne":
		return compareScalar(v, c.Value) != 0, desc()
	case "gt":
		return compareScalar(v, c.Value) > 0, desc()
	case "lt":
		return compareScalar(v, c.Value) < 0, desc()
	case "gte":
		return compareScalar(v, c.Value) >= 0, desc()
	case "lte":
		return compareScalar(v, c.Value) <= 0, desc()
	case "in":
		list := toStrings(c.Value)
		s := lower(stringify(v))
		for _, item := range list {
			if lower(item) == s {
				return true, desc()
			}
		}
		return false, desc()
	case "nin":
		list := toStrings(c.Value)
		s := lower(stringify(v))
		for _, item := range list {
			if lower(item) == s {
				return false, desc()
			}
		}
		return true, desc()
	case "contains":
		return strings.Contains(stringify(v), stringify(c.Value)), desc()
	case "icontains":
		return strings.Contains(lower(stringify(v)), lower(stringify(c.Value))), desc()
	case "ncontains":
		return !strings.Contains(lower(stringify(v)), lower(stringify(c.Value))), desc()
	case "prefix":
		return strings.HasPrefix(lower(stringify(v)), lower(stringify(c.Value))), desc()
	case "isuffix", "suffix":
		return strings.HasSuffix(lower(stringify(v)), lower(stringify(c.Value))), desc()
	case "glob":
		ok, _ := filepath.Match(lower(stringify(c.Value)), lower(stringify(v)))
		return ok, desc()
	case "regex":
		re, err := compileRegex(stringify(c.Value))
		if err != nil {
			return false, desc()
		}
		return re.MatchString(stringify(v)), desc()
	case "any_in_list":
		// 值侧是列表，判断与条件列表是否有交集（用于 ancestor.names）
		want := toStrings(c.Value)
		for _, actual := range toStrings(v) {
			for _, w := range want {
				if lower(actual) == lower(w) {
					return true, desc()
				}
			}
		}
		return false, desc()
	case "list_contains":
		// 值侧本身是列表，判断是否包含条件的标量
		target := lower(stringify(c.Value))
		for _, actual := range toStrings(v) {
			if lower(actual) == target {
				return true, desc()
			}
		}
		return false, desc()
	case "list_has_any":
		// 值侧列表与条件列表求交（用于 remote_ports）
		want := toStrings(c.Value)
		for _, actual := range toStrings(v) {
			for _, w := range want {
				if lower(actual) == lower(w) {
					return true, desc()
				}
			}
		}
		return false, desc()
	case "bool_eq":
		b, _ := toBool(c.Value)
		actual, _ := toBool(v)
		return actual == b, desc()
	}
	return false, desc()
}

func compareScalar(a, b any) int {
	// 数字优先
	if an, aok := toFloat(a); aok {
		if bn, bok := toFloat(b); bok {
			switch {
			case an < bn:
				return -1
			case an > bn:
				return 1
			}
			return 0
		}
	}
	if ab, aok := toBool(a); aok {
		if bb, bok := toBool(b); bok {
			switch {
			case !ab && bb:
				return -1
			case ab && !bb:
				return 1
			}
			return 0
		}
	}
	return strings.Compare(lower(stringify(a)), lower(stringify(b)))
}

func stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	default:
		return fmt.Sprint(x)
	}
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, stringify(e))
		}
		return out
	case string:
		if x == "" {
			return nil
		}
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			out = append(out, strings.TrimSpace(p))
		}
		return out
	default:
		return []string{stringify(v)}
	}
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}

func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(x)
		return b, err == nil
	case float64:
		return x != 0, true
	case int:
		return x != 0, true
	}
	return false, false
}

func lower(s string) string { return strings.ToLower(s) }
