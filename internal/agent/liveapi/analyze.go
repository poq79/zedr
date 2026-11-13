//go:build windows
// +build windows

package liveapi

// analyze.go：/analyze —— 二进制深度分析（契约 §11.1）。
//
// 口径说明（为什么这样设计）：
//   - 三哈希 + strings 窗口采样 = 单遍流式（windowTee 挂在 MultiWriter 上），
//     不为取头尾样本而第二遍读文件；
//   - PE 解析复用同一个已打开的句柄（io.ReaderAt 随机访问），顺序哈希完成
//     后文件偏移停在 EOF，ReadAt（pread）不受影响；
//   - imphash 按 VT 口径：小写 dll!func、dll 去扩展名、排序后拼接取 MD5；
//   - 非 PE 文件 pe/version_resource/packer_hints 三块省略（omitempty），
//     strings 照常——文档/脚本同样是"这个文件里有什么线索"的问题。

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"zedr/internal/agent/winapi"
	"zedr/internal/platform/apperr"
	"zedr/internal/platform/httpx"
	"zedr/internal/platform/redact"
)

const (
	// analyzeMaxBytes 64MB 上限：更大的是镜像/安装包类，熵与导入分析价值
	// 低而 IO 成本高，明确拒绝（与 fs/hash 的 2GB 上限区分开）
	analyzeMaxBytes = 64 << 20
	// analyzeBudget PE 解析预算（契约 §11.1）；超时省略 pe 块而不是 500，
	// 让哈希与字符串线索照常返回
	analyzeBudget = 30 * time.Second
	// stringWindow 采样窗口：头/尾各 64KB（大量壳的字符串堆在头尾）
	stringWindow = 64 << 10
	// entropyBlock 分节熵的分块读取粒度：避免 Section.Data() 一次性把
	// 几十 MB 的节拉进内存
	entropyBlock = 64 << 10
	// stringsPerClass 每类字符串上限（契约 ≤10）
	stringsPerClass = 10
	// notableImports 导入"值得注意"清单上限（契约 ≤20）
	notableImports = 20
)

// reIPv4 只接受完整 IPv4（点分四段），嵌在长串里的 IP 由 extractStrings
// 先切成独立候选，这里负责整串校验。
var reIPv4 = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// analyzeResult 是 /analyze 的响应体（契约 §11.1 字段名）。
type analyzeResult struct {
	Path            string         `json:"path"`
	Size            int64          `json:"size"`
	MD5             string         `json:"md5"`
	SHA1            string         `json:"sha1"`
	SHA256          string         `json:"sha256"`
	PE              *peReport      `json:"pe,omitempty"`
	VersionResource *versionReport `json:"version_resource,omitempty"`
	PackerHints     []string       `json:"packer_hints,omitempty"`
	Strings         stringsReport  `json:"strings"`
}

// peReport 只在 MZ 魔数成立时出现。
type peReport struct {
	Machine           string         `json:"machine"`
	Subsystem         string         `json:"subsystem"`
	IsDLL             bool           `json:"is_dll"`
	CompileTSUnix     int64          `json:"compile_ts_unix"`
	EntryPoint        uint32         `json:"entry_point"`
	Sections          []peSection    `json:"sections"`
	MaxSectionEntropy float64        `json:"max_section_entropy"`
	ImpHash           string         `json:"imphash,omitempty"`
	Imports           *importsReport `json:"imports,omitempty"`
}

type peSection struct {
	Name    string  `json:"name"`
	Size    uint32  `json:"size"`
	Entropy float64 `json:"entropy"`
	Flags   string  `json:"flags"` // COFF Characteristics 原始位（十六进制），前端按位解读
}

type importsReport struct {
	Total      int              `json:"total"`
	Categories importCategories `json:"categories"`
	Notable    []string         `json:"notable,omitempty"`
}

// importCategories 固定七类计数（0 也输出，前端徽标渲染需要键齐全）。
type importCategories struct {
	Network          int `json:"network"`
	ProcessInjection int `json:"process_injection"`
	Persistence      int `json:"persistence"`
	KeyboardHook     int `json:"keyboard_hook"`
	AntiDebug        int `json:"anti_debug"`
	Exec             int `json:"exec"`
	Fs               int `json:"fs"`
}

type versionReport struct {
	Company          string `json:"company"`
	Product          string `json:"product"`
	Description      string `json:"description"`
	OriginalFilename string `json:"original_filename"`
	Mismatch         bool   `json:"mismatch"`
}

type stringsReport struct {
	URLs          []string `json:"urls"`
	IPs           []string `json:"ips"`
	RegistryPaths []string `json:"registry_paths"`
	FilePaths     []string `json:"file_paths"`
	Mutex         []string `json:"mutex"`
}

func (s *server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	path, err := validateFSPath(r.URL.Query().Get("path"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	e, err := s.d.FS.Stat(path)
	if err != nil {
		writeFSErr(w, r, err)
		return
	}
	if e.IsDir {
		httpx.WriteError(w, r, apperr.Invalid("目录无法做二进制分析"))
		return
	}
	if e.Size > analyzeMaxBytes {
		httpx.WriteError(w, r, apperr.Invalid("文件超过 64MB，拒绝分析"))
		return
	}
	rc, size, err := s.d.FS.Open(path)
	if err != nil {
		writeFSErr(w, r, err)
		return
	}
	defer rc.Close()
	// Stat 与 Open 之间的双检（同 /fs/hash 惯例）：文件可能被换成大文件
	if size > analyzeMaxBytes {
		httpx.WriteError(w, r, apperr.Invalid("文件超过 64MB，拒绝分析"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), analyzeBudget)
	defer cancel()
	res, err := s.analyzeFile(ctx, path, rc, size)
	if err != nil {
		httpx.WriteError(w, r, apperr.Internal(err))
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, res)
}

// analyzeFile 执行"单遍哈希 + 窗口采样 + 条件 PE 解析"。
// 读失败返回 error：读一半的哈希是错误结论，绝不能当真值输出。
func (s *server) analyzeFile(ctx context.Context, path string, rc io.ReadCloser, size int64) (analyzeResult, error) {
	res := analyzeResult{Path: path, Strings: stringsReport{
		URLs: []string{}, IPs: []string{}, RegistryPaths: []string{},
		FilePaths: []string{}, Mutex: []string{},
	}}

	md5w, sha1w, sha256w := md5.New(), sha1.New(), sha256.New()
	wt := &windowTee{size: size}
	buf := make([]byte, hashBufSize)
	hashed, err := io.CopyBuffer(io.MultiWriter(md5w, sha1w, sha256w, wt), rc, buf)
	if err != nil {
		return res, fmt.Errorf("读取文件失败: %w", err)
	}
	res.Size = hashed
	res.MD5 = hex.EncodeToString(md5w.Sum(nil))
	res.SHA1 = hex.EncodeToString(sha1w.Sum(nil))
	res.SHA256 = hex.EncodeToString(sha256w.Sum(nil))

	// strings 采样：头尾窗口去重合并（≤128KB 的文件 head+tail 有重叠）
	samples := make([]byte, 0, len(wt.head)+len(wt.tail))
	samples = append(samples, wt.head...)
	samples = append(samples, wt.tail...)
	res.Strings = classifyStrings(extractStrings(samples))

	isPE := len(wt.head) >= 2 && wt.head[0] == 'M' && wt.head[1] == 'Z'
	if !isPE {
		return res, nil
	}

	ra, ok := rc.(io.ReaderAt)
	if !ok {
		// 桩实现可能不支持随机访问：PE 块省略，其余结论仍然成立
		slog.Warn("analyze_pe_skipped_no_readerat", "path", redact.Path(path))
		return res, nil
	}
	rep, hints := s.parsePE(ctx, ra, path)
	if rep != nil {
		res.PE = rep
		res.PackerHints = hints
		if vr, verr := winapi.ReadVersionInfo(path); verr == nil && vr != nil {
			res.VersionResource = &versionReport{
				Company:          vr.Company,
				Product:          vr.Product,
				Description:      vr.Description,
				OriginalFilename: vr.OriginalFilename,
				// 伪装信号：资源里声明的原始文件名与实际名不符
				//（casefold 比较，Windows 文件名本就不区分大小写）
				Mismatch: vr.OriginalFilename != "" &&
					!strings.EqualFold(vr.OriginalFilename, filepath.Base(path)),
			}
		}
	}
	return res, nil
}

// parsePE 解析 PE 结构；损坏 PE（MZ 头但后续解析失败）返回 nil, nil——
// "MZ 头但不是合法 PE"本身少见且可疑，此时宁缺毋滥不伪造结论。
func (s *server) parsePE(ctx context.Context, ra io.ReaderAt, path string) (*peReport, []string) {
	pf, err := pe.NewFile(ra)
	if err != nil {
		slog.Info("analyze_pe_parse_failed", "path", redact.Path(path), "err", err.Error())
		return nil, nil
	}
	defer pf.Close()

	rep := &peReport{
		Machine:       machineName(pf.FileHeader.Machine),
		IsDLL:         pf.FileHeader.Characteristics&0x2000 != 0, // IMAGE_FILE_DLL
		CompileTSUnix: int64(pf.FileHeader.TimeDateStamp),
	}
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		rep.Subsystem = subsystemName(oh.Subsystem)
		rep.EntryPoint = oh.AddressOfEntryPoint
	case *pe.OptionalHeader32:
		rep.Subsystem = subsystemName(oh.Subsystem)
		rep.EntryPoint = oh.AddressOfEntryPoint
	}

	// 分节：熵 + 加壳提示。任一环节超预算 → 省略 pe 整块（半份 PE 报告
	// 比没有更误导，前端无从知道哪些节是猜的）
	var hints []string
	maxEnt := 0.0
	sections := make([]peSection, 0, len(pf.Sections))
	for _, sec := range pf.Sections {
		if ctx.Err() != nil {
			slog.Warn("analyze_pe_budget_exceeded", "path", redact.Path(path), "at", "sections")
			return nil, nil
		}
		ent := sectionEntropy(ctx, ra, sec)
		name := sec.Name
		sections = append(sections, peSection{
			// Go 1.27 的 pe.SectionHeader 用 Size/Offset 命名（对应传统
			// 口径的 SizeOfRawData/PointerToRawData，磁盘布局字段）
			Name:    name,
			Size:    sec.Size, // 磁盘口径：熵是对磁盘字节算的
			Entropy: ent,
			Flags:   fmt.Sprintf("0x%08x", sec.Characteristics),
		})
		if ent > maxEnt {
			maxEnt = ent
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, "upx") || strings.Contains(lower, "aspack") || strings.Contains(lower, "themida") {
			hints = append(hints, fmt.Sprintf("%s 节", name))
		}
	}
	rep.Sections = sections
	rep.MaxSectionEntropy = maxEnt
	if maxEnt > 7.2 {
		// 只报最高熵节：多个高熵节逐条报会把提示列表撑爆
		hints = append(hints, fmt.Sprintf("节熵 %.1f", maxEnt))
	}

	// 导入表：imphash（VT 口径）+ 类别映射。
	// Go 1.27 的 ImportedSymbols 返回格式是 "func:DLL"（函数在前、冒号
	// 分隔，ordinal 导入被库直接跳过）——不是传统工具链的 "dll!func"，
	// 这里先归一成统一的 dll!func 再进后续口径。
	syms, err := pf.ImportedSymbols()
	if err != nil {
		// 静态链接（Go/C 静态）无导入表是常态，不算失败
		return rep, hints
	}
	normalized := make([]string, 0, len(syms))
	cats := importCategories{}
	seen := map[string]struct{}{}
	var notable []string
	for _, sym := range syms {
		fn, dll, ok := strings.Cut(sym, ":")
		if !ok {
			continue
		}
		fn = strings.ToLower(fn)
		dll = strings.ToLower(dll)
		// VT 口径：dll 去扩展名（kernel32.dll → kernel32）
		if i := strings.LastIndex(dll, "."); i >= 0 {
			dll = dll[:i]
		}
		normalized = append(normalized, dll+"!"+fn)
		hits := classifyImport(dll, fn)
		if len(hits) == 0 {
			continue
		}
		for _, c := range hits {
			cats.apply(c)
		}
		if len(notable) < notableImports {
			if _, dup := seen[sym]; !dup {
				seen[sym] = struct{}{}
				notable = append(notable, dll+"!"+fn)
			}
		}
	}
	rep.Imports = &importsReport{Total: len(normalized), Categories: cats, Notable: notable}
	if len(normalized) > 0 {
		sort.Strings(normalized)
		// 分隔符取逗号（与 pefile 的 imphash 串一致）；本口径其余细节
		//（小写、去扩展名、排序）以契约 §11.1 为准
		sum := md5.Sum([]byte(strings.Join(normalized, ",")))
		rep.ImpHash = hex.EncodeToString(sum[:])
	}
	return rep, hints
}

// importRule 类别映射规则：network 按 DLL 名匹配，其余按函数名匹配
// （契约：DLL 名归不了的函数不计入类别）。
type importRule struct {
	cat string
	dll []string
	fn  []string
}

var importRules = []importRule{
	{cat: "network", dll: []string{"ws2_32", "wininet", "winhttp", "dnsapi"}},
	{cat: "process_injection", fn: []string{"virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection"}},
	{cat: "keyboard_hook", fn: []string{"setwindowshookex", "getasynckeystate"}},
	{cat: "persistence", fn: []string{"regsetvalueex", "regcreatekey"}},
	{cat: "anti_debug", fn: []string{"isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring"}},
	{cat: "exec", fn: []string{"winexec", "shellexecute", "createprocess"}},
	{cat: "fs", fn: []string{"writefile", "deletefile", "movefile"}},
}

// classifyImport 返回该导入命中的类别（可能多个：一个函数可同时具备
// 多类特征，如 RegCreateKeyExW 命中 persistence）。
func classifyImport(dll, fn string) []string {
	var out []string
	for _, rule := range importRules {
		for _, k := range rule.dll {
			if strings.Contains(dll, k) {
				out = append(out, rule.cat)
				break
			}
		}
		for _, k := range rule.fn {
			if strings.Contains(fn, k) {
				out = append(out, rule.cat)
				break
			}
		}
	}
	return out
}

func (c *importCategories) apply(cat string) {
	switch cat {
	case "network":
		c.Network++
	case "process_injection":
		c.ProcessInjection++
	case "persistence":
		c.Persistence++
	case "keyboard_hook":
		c.KeyboardHook++
	case "anti_debug":
		c.AntiDebug++
	case "exec":
		c.Exec++
	case "fs":
		c.Fs++
	}
}

// sectionEntropy 分块读算香农熵（Offset=0 的节无磁盘数据 → 0）。
func sectionEntropy(ctx context.Context, ra io.ReaderAt, sec *pe.Section) float64 {
	off, n := int64(sec.Offset), int64(sec.Size)
	if off == 0 || n == 0 {
		return 0
	}
	var (
		hist  [256]int64
		total int64
		block [entropyBlock]byte
	)
	for read := int64(0); read < n; {
		want := int64(entropyBlock)
		if n-read < want {
			want = n - read
		}
		got, err := ra.ReadAt(block[:want], off+read)
		read += int64(got)
		total += int64(got)
		for _, b := range block[:got] {
			hist[b]++
		}
		if err != nil || ctx.Err() != nil {
			break
		}
	}
	if total == 0 {
		return 0
	}
	ent := 0.0
	for _, c := range hist {
		if c > 0 {
			p := float64(c) / float64(total)
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func machineName(m uint16) string {
	switch m {
	case 0x8664:
		return "x86_64"
	case 0x14c:
		return "i386"
	case 0xaa64:
		return "arm64"
	case 0x1c0, 0x1c4:
		return "arm"
	default:
		return fmt.Sprintf("0x%04x", m)
	}
}

func subsystemName(s uint16) string {
	switch s {
	case 1:
		return "native"
	case 2:
		return "gui"
	case 3:
		return "console"
	case 9:
		return "windows_ce"
	case 10, 11, 12, 13:
		return "efi"
	default:
		return fmt.Sprintf("%d", s)
	}
}

// ---------------------------------------------------------------- 窗口采样

// windowTee 挂在 MultiWriter 上：流经的字节里截出头/尾 64KB 样本。
// 与哈希共用一次读取，是"单遍"口径的实现细节。
type windowTee struct {
	size int64
	pos  int64
	head []byte
	tail []byte
}

func (wt *windowTee) Write(p []byte) (int, error) {
	n := len(p)
	end := wt.pos + int64(n)
	// 头窗口 [0, 64KB)
	if wt.pos < stringWindow {
		want := int64(n)
		if end > stringWindow {
			want = stringWindow - wt.pos
		}
		if want > 0 {
			wt.head = append(wt.head, p[:want]...)
		}
	}
	// 尾窗口 [size-64KB, size)。size ≤ 64KB 时尾窗口为负区间，整文件
	// 已被头窗口覆盖，无需重复采集
	if tailStart := wt.size - stringWindow; tailStart > 0 && end > tailStart {
		from := wt.pos
		if from < tailStart {
			from = tailStart
		}
		to := end
		if to > wt.size {
			to = wt.size
		}
		wt.tail = append(wt.tail, p[from-wt.pos:to-wt.pos]...)
	}
	wt.pos = end
	return n, nil
}

// ---------------------------------------------------------------- 字符串提取与分类

// extractStrings 从采样字节中提取 ≥5 字符的可打印 ASCII 与 UTF-16LE 串。
// UTF-16 按偶数偏移扫（Windows 宽字符数据 2 字节对齐，奇偏移会提出错位串）。
func extractStrings(b []byte) []string {
	var out []string
	// ASCII：连续可打印字节
	start := -1
	for i := 0; i <= len(b); i++ {
		printable := i < len(b) && b[i] >= 0x20 && b[i] <= 0x7e
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 5 {
			out = append(out, string(b[start:i]))
		}
		start = -1
	}
	// UTF-16LE：低字节可打印 ASCII 且高字节为 0。
	// 理论上宽字符数据 2 字节对齐，但采样窗口起点与壳对齐都可能错位，
	// 偶/奇偏移各扫一遍（成本 ×2 但窗口只有 128KB）。
	// 注意必须逐 word 取低字节"解码"成串——直接 string(原始字节) 会带
	// NUL 间隔，后续前缀分类全部失配（踩过：URL 全部漏检）。
	for _, offset := range [2]int{0, 1} {
		start := -1
		flush := func(i int) {
			if start < 0 || (i-start)/2 < 5 {
				return
			}
			var sb []byte
			for j := start; j < i; j += 2 {
				sb = append(sb, b[j])
			}
			out = append(out, string(sb))
		}
		for i := offset; i+1 < len(b); i += 2 {
			printable := b[i] >= 0x20 && b[i] <= 0x7e && b[i+1] == 0
			if printable {
				if start < 0 {
					start = i
				}
				continue
			}
			flush(i)
			start = -1
		}
		// 尾串收口：终点取最后一个完整 word 的边界
		flush(offset + (len(b)-offset)/2*2)
	}
	return out
}

// classifyStrings 按优先级分类（每串只进一类），去重且每类 ≤10。
// 优先级 mutex → URL → IP → registry → filepath：前缀越特殊越先判，
// 避免 "Global\http_tunnel_mutex" 这类串被 URL 规则截走。
func classifyStrings(samples []string) stringsReport {
	rep := stringsReport{
		URLs: []string{}, IPs: []string{}, RegistryPaths: []string{},
		FilePaths: []string{}, Mutex: []string{},
	}
	add := func(dst *[]string, seen map[string]struct{}, v string) {
		if _, dup := seen[v]; dup {
			return
		}
		if len(*dst) >= stringsPerClass {
			return
		}
		seen[v] = struct{}{}
		*dst = append(*dst, v)
	}
	seen := map[string]struct{}{}
	for _, s := range samples {
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(low, `global\`):
			add(&rep.Mutex, seen, s)
		case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
			add(&rep.URLs, seen, s)
		case reIPv4.MatchString(s):
			add(&rep.IPs, seen, s)
		case strings.HasPrefix(low, "hklm"), strings.HasPrefix(low, "hkcu"), strings.HasPrefix(low, "hkey"):
			add(&rep.RegistryPaths, seen, s)
		case (len(s) >= 3 && isASCIILetter(s[0]) && s[1] == ':'), strings.HasPrefix(s, "%"):
			add(&rep.FilePaths, seen, s)
		}
	}
	return rep
}

func isASCIILetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
