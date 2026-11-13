//go:build windows
// +build windows

package liveapi

// registry.go：/registry 注册表只读查询端点（隧道内调查面，LiveFS 之外
// 补注册表一块，供 AI 调查/狩猎核对自启动键、服务参数、策略配置等）。
//
// 设计口径：
//   - 只读铁律：OpenKey 仅带 QUERY_VALUE|ENUMERATE_SUB_KEYS 访问权，
//     本文件不存在任何 Set/Delete/Create 调用；
//   - 根键白名单 HKLM/HKCU/HKU/HKCR：HKCC/HKPD 等对入侵调查价值低，
//     v1 先收紧查询面；
//   - 键不存在 → 200 exists:false（学 /fs/stat："在不在"本身是调查结论，
//     404 会让前端把正常排查当故障）；
//   - 键打开被拒（SAM/SECURITY 等 ACL 保护键）→ 403，与 /fs、/accounts
//     的权限错误口径一致；
//   - 单个值读不出（ACL/类型异常/超大）→ 该值 data:null + error 短说明，
//     其余值照常返回，整体不 500——保护键下部分可读的值对调查仍有价值，
//     整页失败反而让调查员什么都看不到。
//
// EXPAND_SZ 的返回口径：data 为未展开原文（调查需要看到 %VAR% 模板原文，
// 驻留手法常借环境变量藏路径），expanded 字段给出展开后文本（仅当展开
// 成功且与原文不同时输出），两者都有才是完整证据。

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
)

// 参数上限（queryInt 双侧钳制的探针侧，与包内其他端点同纪律）。
const (
	regDefaultSubkeys = 200
	regMaxSubkeys     = 1000
	regDefaultValues  = 100
	regMaxValues      = 500

	regBinaryHexBytes  = 1024      // BINARY 值的 hex 预览上限（原始字节数）
	regMultiSZMaxItems = 32        // MULTI_SZ 返回条数上限
	regMaxValueBytes   = 256 << 10 // 单个值数据抓取上限，防线隧道响应体被超大值撑爆
)

// regRoots 是根键白名单：只有对调查有价值的四个标准根键。
// 查询面收紧的意义与 fs 端点拒绝设备命名空间一致——隧道内接口
// 暴露面越小，误用与滥用的成本越高。
var regRoots = map[string]registry.Key{
	"HKLM": registry.LOCAL_MACHINE,
	"HKCU": registry.CURRENT_USER,
	"HKU":  registry.USERS,
	"HKCR": registry.CLASSES_ROOT,
}

// errRegValueTooLarge 哨兵：值数据超过抓取上限（区别于系统级读失败）。
var errRegValueTooLarge = errors.New("value too large")

// regValue 是 values[] 的一项。Data 按类型多态：
// SZ/EXPAND_SZ/LINK→string，MULTI_SZ→[]string，DWORD/QWORD→数字，
// BINARY 及未识别类型→hex 字符串（截 1KB，truncated 标记）。
type regValue struct {
	Name      string `json:"name"` // "" 为键的默认值（(Default)）
	Type      string `json:"type"`
	Data      any    `json:"data"`
	Expanded  string `json:"expanded,omitempty"`  // EXPAND_SZ 展开后文本（成功且与原文不同时）
	Truncated bool   `json:"truncated,omitempty"` // BINARY 截 1KB / MULTI_SZ 截 32 项
	Error     string `json:"error,omitempty"`     // 该值读取失败（ACL/超大）的短说明，此时 data 为 null
}

// registryResult 是 /registry 的完整响应（httpx.WriteJSON 包进 data）。
type registryResult struct {
	Path             string     `json:"path"`
	Exists           bool       `json:"exists"`
	Subkeys          []string   `json:"subkeys"`
	TruncatedSubkeys bool       `json:"truncated_subkeys"`
	Values           []regValue `json:"values"`
	TruncatedValues  bool       `json:"truncated_values"`
}

// parseRegPath 解析并校验 path 参数，返回 (根键, 子键路径, 规范显示路径)。
// 接受 '\' 或 '/' 分隔（前端/调查员粘贴两种形态都常见）；根键大小写
// 不敏感并归一为大写标准形，子键保留原大小写（注册表大小写不敏感但
// 大小写保留，调查输出应还原真实键名）。
func parseRegPath(raw string) (registry.Key, string, string, error) {
	if raw == "" {
		return 0, "", "", apperr.Invalid("path 参数必填")
	}
	segs := strings.Split(strings.ReplaceAll(raw, "/", "\\"), "\\")
	root, ok := regRoots[strings.ToUpper(segs[0])]
	if !ok {
		return 0, "", "", apperr.Invalid("根键必须是 HKLM/HKCU/HKU/HKCR 之一")
	}
	for _, s := range segs[1:] {
		if s == ".." {
			// 注册表没有目录穿越，但统一按 fs 端点的敌意输入口径拒绝：
			// 拼接进显示路径/日志时会制造歧义
			return 0, "", "", apperr.Invalid("path 不允许包含 ..")
		}
		if s == "" {
			// 覆盖结尾分隔符（粘贴痕迹）与连续分隔符：空段一律拒绝，
			// 避免 "HKLM\\SOFTWARE\\" 与 "HKLM\\SOFTWARE" 两种输入产生
			// 不同的日志/展示形态
			return 0, "", "", apperr.Invalid("path 含空路径段")
		}
	}
	sub := strings.Join(segs[1:], "\\")
	display := strings.ToUpper(segs[0])
	if sub != "" {
		display += "\\" + sub
	}
	return root, sub, display, nil
}

func (s *server) handleRegistry(w http.ResponseWriter, r *http.Request) {
	root, sub, display, err := parseRegPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	maxSub := queryInt(r, "max_subkeys", regDefaultSubkeys, 1, regMaxSubkeys)
	maxVal := queryInt(r, "max_values", regDefaultValues, 1, regMaxValues)

	k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if writeRegOpenErr(w, r, err) {
			return
		}
		// 键不存在 → 200 exists:false（学 /fs/stat 语义）
		httpx.WriteJSON(w, r, http.StatusOK, registryResult{
			Path:    display,
			Exists:  false,
			Subkeys: []string{},
			Values:  []regValue{},
		})
		return
	}
	defer k.Close()

	// Stat 的计数是截断判定的权威口径：枚举中途失败（罕见）时
	// "取得数 < 计数"也能被如实标出，而不是静默漏项
	subTotal, valTotal := -1, -1
	if ki, statErr := k.Stat(); statErr == nil {
		subTotal, valTotal = int(ki.SubKeyCount), int(ki.ValueCount)
	}

	res := registryResult{Path: display, Exists: true}

	// ReadSubKeyNames/ReadValueNames 传 -1 取全量：x/sys 在 n>0 且实际
	// 条数少于 n 时会带 io.EOF 返回，且两种形态都不带截断标记——
	// 截断必须在这里自己做
	subNames, subErr := k.ReadSubKeyNames(-1)
	if subErr != nil {
		// 部分枚举失败不失败整个请求：已取得的子键名单照常返回
		slog.Warn("liveapi_registry_subkeys_partial", "path", display, "err", subErr)
	}
	if len(subNames) > maxSub {
		subNames = subNames[:maxSub]
	}
	if subNames == nil {
		subNames = []string{}
	}
	res.Subkeys = subNames
	res.TruncatedSubkeys = subTotal > len(subNames)

	valNames, valErr := k.ReadValueNames(-1)
	if valErr != nil {
		slog.Warn("liveapi_registry_values_partial", "path", display, "err", valErr)
	}
	if len(valNames) > maxVal {
		valNames = valNames[:maxVal]
	}
	res.TruncatedValues = valTotal > len(valNames)
	// 先截名字再读数据：值数据逐条要走 RegQueryValueEx 往返，
	// 超出上限的名字不去白付那次成本
	vals := make([]regValue, 0, len(valNames))
	for _, name := range valNames {
		vals = append(vals, readRegValue(k, name))
	}
	res.Values = vals

	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// writeRegOpenErr 把键打开失败映射为规范错误；返回 false 表示"键不存在"，
// 由调用方按 200 exists:false 继续（这是调查结论不是故障）。
func writeRegOpenErr(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return false
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		slog.Warn("liveapi_registry_open_denied", "err", err)
		httpx.WriteError(w, r, apperr.Forbidden("注册表键访问被系统拒绝"))
	default:
		slog.Warn("liveapi_registry_open_failed", "err", err)
		httpx.WriteError(w, r, apperr.Internal(err))
	}
	return true
}

// readRegValue 读取单个值并按类型解码。任何失败都收敛为
// data:null + error 短说明，绝不 panic、绝不 500 整页。
func readRegValue(k registry.Key, name string) regValue {
	v := regValue{Name: name}
	raw, vt, err := regRawValue(k, name)
	if err != nil {
		if errors.Is(err, errRegValueTooLarge) {
			// "缓冲不足"失败路径上类型仍然已知，照实返回
			v.Type = regTypeName(vt)
			v.Error = "值数据超过 256KB 上限，拒绝返回"
			return v
		}
		// ACL 拒绝等系统级失败拿不到类型：留空由 error 说明
		v.Error = err.Error()
		return v
	}
	v.Type = regTypeName(vt)
	switch vt {
	case registry.SZ, registry.LINK:
		v.Data = utf16BytesToString(raw)
	case registry.EXPAND_SZ:
		rawStr := utf16BytesToString(raw)
		v.Data = rawStr
		if exp, e := registry.ExpandString(rawStr); e == nil && exp != rawStr {
			v.Expanded = exp
		}
	case registry.MULTI_SZ:
		items := multiSZStrings(raw)
		if len(items) > regMultiSZMaxItems {
			items = items[:regMultiSZMaxItems]
			v.Truncated = true
		}
		if items == nil {
			items = []string{}
		}
		v.Data = items
	case registry.DWORD:
		if len(raw) >= 4 {
			v.Data = uint64(binary.LittleEndian.Uint32(raw))
		} else {
			v.Error = "DWORD 数据长度异常"
		}
	case registry.DWORD_BIG_ENDIAN:
		if len(raw) >= 4 {
			v.Data = uint64(binary.BigEndian.Uint32(raw))
		} else {
			v.Error = "DWORD_BIG_ENDIAN 数据长度异常"
		}
	case registry.QWORD:
		if len(raw) >= 8 {
			v.Data = binary.LittleEndian.Uint64(raw)
		} else {
			v.Error = "QWORD 数据长度异常"
		}
	default:
		// BINARY 与未识别类型（RESOURCE_LIST 等）：hex 预览，截 1KB。
		// 未识别类型不猜语义，给原始字节让调查员/上层模型自行判断
		preview := raw
		if len(preview) > regBinaryHexBytes {
			preview = preview[:regBinaryHexBytes]
			v.Truncated = true
		}
		v.Data = hex.EncodeToString(preview)
	}
	return v
}

// regRawValue 抓取一个值的原始数据与类型。两段式：先小缓冲试读，
// 缓冲不足按系统报告的精确大小重试一次——值数据在两次调用之间可能
// 被并发改大，重试仍不足就按超大处理，不做无限循环。
func regRawValue(k registry.Key, name string) ([]byte, uint32, error) {
	buf := make([]byte, 64)
	n, vt, err := k.GetValue(name, buf)
	if err == nil {
		return buf[:n], vt, nil
	}
	if !errors.Is(err, registry.ErrShortBuffer) {
		return nil, vt, err
	}
	if n < 0 {
		return nil, vt, nil
	}
	if n > regMaxValueBytes {
		return nil, vt, errRegValueTooLarge
	}
	buf = make([]byte, n)
	n, vt, err = k.GetValue(name, buf)
	if err != nil {
		if errors.Is(err, registry.ErrShortBuffer) {
			return nil, vt, errRegValueTooLarge
		}
		return nil, vt, err
	}
	return buf[:n], vt, nil
}

// regTypeName 把值类型码映射为 Windows 文档名；未识别的码照实带编号
// 返回（REG_ 前缀省去，前端展示层自行补），不猜测语义。
func regTypeName(vt uint32) string {
	switch vt {
	case registry.NONE:
		return "NONE"
	case registry.SZ:
		return "SZ"
	case registry.EXPAND_SZ:
		return "EXPAND_SZ"
	case registry.BINARY:
		return "BINARY"
	case registry.DWORD:
		return "DWORD"
	case registry.DWORD_BIG_ENDIAN:
		return "DWORD_BIG_ENDIAN"
	case registry.LINK:
		return "LINK"
	case registry.MULTI_SZ:
		return "MULTI_SZ"
	case registry.RESOURCE_LIST:
		return "RESOURCE_LIST"
	case registry.FULL_RESOURCE_DESCRIPTOR:
		return "FULL_RESOURCE_DESCRIPTOR"
	case registry.RESOURCE_REQUIREMENTS_LIST:
		return "RESOURCE_REQUIREMENTS_LIST"
	case registry.QWORD:
		return "QWORD"
	default:
		return "UNKNOWN"
	}
}

// utf16BytesToUint16 把小端 UTF-16 字节流转成码元切片（两个解码函数共用）。
func utf16BytesToUint16(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return u
}

// utf16BytesToString 解码 SZ/EXPAND_SZ/LINK 的数据面。系统可能返回
// 不带终止 NUL 的串（文档明说允许），UTF16ToString 按切片长度兜底。
func utf16BytesToString(b []byte) string {
	return windows.UTF16ToString(utf16BytesToUint16(b))
}

// multiSZStrings 解码 MULTI_SZ：单 NUL 分段、双 NUL 终止。遇空段
// （连续 NUL）即按终止符处理——畸形数据宁少勿错，不猜后半段语义。
func multiSZStrings(b []byte) []string {
	u := utf16BytesToUint16(b)
	if u == nil {
		return nil
	}
	var out []string
	start := 0
	for i, c := range u {
		if c != 0 {
			continue
		}
		if i == start {
			break
		}
		out = append(out, windows.UTF16ToString(u[start:i]))
		start = i + 1
	}
	return out
}
