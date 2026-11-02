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
//
// 严格校验字段与操作符：拼错一个字段名在运行时只会"永远不命中"，
// 没有报错、没有日志，是最难发现的规则失效方式（本仓库 5.1 节
// 的引号编码事故就是同类：规则看似存在，实际从未生效）。
// 因此未知字段/操作符、非法正则/glob、类型不匹配、未知 JSON 键
// 一律在加载期拒绝，让问题在保存规则时就暴露。
func Compile(defJSON string) (*Definition, error) {
	if strings.TrimSpace(defJSON) == "" {
		return nil, fmt.Errorf("规则定义不能为空")
	}
	var d Definition
	dec := json.NewDecoder(strings.NewReader(defJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("规则定义 JSON 解析失败: %w", err)
	}
	if len(d.All) == 0 && len(d.Any) == 0 && len(d.None) == 0 {
		return nil, fmt.Errorf("规则定义至少要包含 all / any / none 之一")
	}
	idx := 0
	for _, group := range [][]Condition{d.All, d.Any, d.None} {
		for _, c := range group {
			idx++
			if err := validateCondition(idx, c); err != nil {
				return nil, err
			}
		}
	}
	return &d, nil
}

// fieldKind 是字段的取值类型，用来在编译期挡住明显的类型错配。
type fieldKind int

const (
	kindString fieldKind = iota
	kindBool
	kindInt
	kindStringList
	kindIntList
)

// validFields 是规则 DSL 的完整字段表。新增 Target 字段时必须同步
// 这里，否则规则能写但加载会被拒绝——这是有意的：宁可在保存时报错。
var validFields = map[string]fieldKind{
	"process.name": kindString, "proc.name": kindString,
	"process.path": kindString, "proc.path": kindString,
	"process.cmdline": kindString, "proc.cmdline": kindString,
	"process.user": kindString, "proc.user": kindString,
	"process.signed":         kindBool,
	"process.signature_ok":   kindBool,
	"process.signer":         kindString,
	"process.elevated":       kindBool,
	"process.in_system":      kindBool,
	"process.dir_writable":   kindBool,
	"process.session":        kindInt,
	"process.depth":          kindInt,
	"parent.name":            kindString,
	"parent.path":            kindString,
	"ancestor.names":         kindStringList,
	"network.count":          kindInt,
	"network.remote_ports":   kindIntList,
	"network.has_public_remote": kindBool,
	"module.unsigned_count":  kindInt,
	"module.non_system_count": kindInt,
}

var validOps = map[string]struct{}{
	"exists": {}, "eq": {}, "ne": {}, "gt": {}, "lt": {}, "gte": {}, "lte": {},
	"in": {}, "nin": {}, "contains": {}, "icontains": {}, "ncontains": {},
	"prefix": {}, "isuffix": {}, "suffix": {}, "glob": {}, "regex": {},
	"any_in_list": {}, "list_contains": {}, "list_has_any": {}, "bool_eq": {},
}

func validateCondition(idx int, c Condition) error {
	kind, ok := validFields[c.Field]
	if !ok {
		return fmt.Errorf("第 %d 个条件: 未知字段 %q（拼写错误会让规则永远不命中）", idx, c.Field)
	}
	if _, ok := validOps[c.Op]; !ok {
		return fmt.Errorf("第 %d 个条件: 未知操作符 %q", idx, c.Op)
	}
	if c.Value == nil && c.Op != "exists" {
		return fmt.Errorf("第 %d 个条件: 操作符 %q 缺少 value", idx, c.Op)
	}

	switch c.Op {
	case "regex":
		s, ok := c.Value.(string)
		if !ok {
			return fmt.Errorf("第 %d 个条件: regex 的 value 必须是字符串", idx)
		}
		if _, err := compileRegex(s); err != nil {
			return fmt.Errorf("第 %d 个条件: 正则非法: %w", idx, err)
		}
	case "glob":
		s, ok := c.Value.(string)
		if !ok {
			return fmt.Errorf("第 %d 个条件: glob 的 value 必须是字符串", idx)
		}
		if _, err := filepath.Match(strings.ToLower(s), ""); err != nil {
			return fmt.Errorf("第 %d 个条件: glob 非法: %w", idx, err)
		}
	case "gt", "lt", "gte", "lte":
		if kind == kindBool || kind == kindStringList || kind == kindIntList {
			return fmt.Errorf("第 %d 个条件: 字段 %q 不支持数值比较", idx, c.Field)
		}
		if kind == kindInt {
			if _, ok := toFloat(c.Value); !ok {
				return fmt.Errorf("第 %d 个条件: 字段 %q 需要数值，得到 %T", idx, c.Field, c.Value)
			}
		}
	case "bool_eq":
		if kind != kindBool {
			return fmt.Errorf("第 %d 个条件: bool_eq 只能用于布尔字段，%q 不是", idx, c.Field)
		}
		if _, ok := toBool(c.Value); !ok {
			return fmt.Errorf("第 %d 个条件: bool_eq 的 value 必须是布尔值", idx)
		}
	case "in", "nin":
		switch c.Value.(type) {
		case string, []string, []any, float64, int, int64, bool:
		default:
			return fmt.Errorf("第 %d 个条件: %s 的 value 必须是列表或标量", idx, c.Op)
		}
	case "any_in_list", "list_has_any":
		if kind != kindStringList && kind != kindIntList {
			return fmt.Errorf("第 %d 个条件: %s 只能用于列表字段，%q 不是", idx, c.Op, c.Field)
		}
		switch c.Value.(type) {
		case string, []string, []any:
		default:
			return fmt.Errorf("第 %d 个条件: %s 的 value 必须是列表或字符串", idx, c.Op)
		}
	case "list_contains":
		if kind != kindStringList && kind != kindIntList {
			return fmt.Errorf("第 %d 个条件: list_contains 只能用于列表字段，%q 不是", idx, c.Field)
		}
	case "contains", "icontains", "ncontains", "prefix", "isuffix", "suffix":
		if kind != kindString && kind != kindStringList {
			return fmt.Errorf("第 %d 个条件: 字段 %q 不支持字符串匹配", idx, c.Field)
		}
	}
	return nil
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
