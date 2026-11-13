//go:build windows
// +build windows

package liveapi

// fs_grep_test.go：/fs/grep 端点。真实临时文件走默认 OSFS（先例同
// fs_test.go/search_test.go）；预算分支靠注入 grepMaxScanBytes / grepBudget
// （先例同 search_test.go 的负预算）；读错误分支用 errFS 桩（真实文件造不出
// 中途读失败）。
// 路由接线归 liveapi.go New()（主线会话），这里本地等价注册保证独立可跑。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// grepHandler 本地等价注册：与 New() 的接线完全一致（同一个 handler 方法、
// 同一层 recoverWrap），仅路由表独立，等主线会话把 /fs/grep 挂进 New() 后
// 两种构造行为相同。
func grepHandler(d Deps) http.Handler {
	if d.FS == nil {
		d.FS = OSFS{}
	}
	s := &server{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /fs/grep", s.handleFSGrep)
	return recoverWrap(mux)
}

// grepTarget 拼 /fs/grep 查询串（extra 追加裸 k=v 对）。
func grepTarget(path, pattern string, extra ...string) string {
	q := "/fs/grep?path=" + url.QueryEscape(path) + "&pattern=" + url.QueryEscape(pattern)
	for _, e := range extra {
		q += "&" + e
	}
	return q
}

// grepItem 与契约字段名逐字对拍（JSON tag 改名即在此炸出）。
type grepItem struct {
	LineNo        int    `json:"line_no"`
	Line          string `json:"line"`
	LineTruncated bool   `json:"line_truncated"`
	Offset        int64  `json:"offset"`
}

func grepItems(t *testing.T, d map[string]any) []grepItem {
	t.Helper()
	raw, err := json.Marshal(d["items"])
	if err != nil {
		t.Fatal(err)
	}
	var items []grepItem
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("items 结构不符: %v raw=%s", err, raw)
	}
	return items
}

// TestGrepBasicMultiLine 多行文本命中：含中文行（rune 边界不腰斩）、CRLF
// 行尾剥离、offset 精确性、首个命中落在嗅探窗口内（回灌回归：嗅探借出的
// 字节必须参与扫描，否则前 512B 内的命中全部丢失）。
func TestGrepBasicMultiLine(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "app.log")
	lines := []string{
		"2026-11-09 10:00:00 [INFO] service boot ok", // 不命中
		"第一行发现 token=abc123 凭据泄露",                    // 命中（含中文）
		"普通填充行，没有线索",                                 // 不命中
		"again token=def456 at the end",              // 命中
		"尾部行 token= 不是命中",                            // "token=" 后无 \w，不命中
	}
	content := strings.Join(lines, "\r\n") + "\r\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := grepHandler(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, grepTarget(p, `token=\w+`))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["path"] != filepath.Clean(p) || d["pattern"] != `token=\w+` {
		t.Errorf("path/pattern 回显不符: %v %v", d["path"], d["pattern"])
	}
	if d["matched"] != float64(2) || d["truncated"] != false {
		t.Errorf("matched/truncated 不符: %v %v", d["matched"], d["truncated"])
	}
	if sb, ok := d["scanned_bytes"].(float64); !ok || int64(sb) != int64(len(content)) {
		t.Errorf("scanned_bytes 期望全量 %d 实得 %v", len(content), d["scanned_bytes"])
	}
	if _, ok := d["is_binary"]; ok {
		t.Errorf("文本文件不应出现 is_binary: %v", d)
	}
	if _, ok := d["elapsed_ms"]; !ok {
		t.Errorf("缺 elapsed_ms: %v", d)
	}

	items := grepItems(t, d)
	if len(items) != 2 {
		t.Fatalf("期望 2 条命中实得 %d: %+v", len(items), items)
	}
	// 首个命中在前 512B 内——嗅探回灌若失效，这里直接漏检
	if items[0].LineNo != 2 || items[0].Line != lines[1] || items[0].LineTruncated {
		t.Errorf("命中 1 不符: %+v", items[0])
	}
	// CRLF 算 2 字节：偏移 = 之前各行字节和 + 每行 2 字节行尾
	off := func(idx int) int64 {
		var n int64
		for i := 0; i < idx; i++ {
			n += int64(len(lines[i]) + 2)
		}
		return n
	}
	if items[0].Offset != off(1) {
		t.Errorf("命中 1 offset 期望 %d 实得 %d", off(1), items[0].Offset)
	}
	if items[1].LineNo != 4 || items[1].Line != lines[3] {
		t.Errorf("命中 2 不符: %+v", items[1])
	}
	if items[1].Offset != off(3) {
		t.Errorf("命中 2 offset 期望 %d 实得 %d", off(3), items[1].Offset)
	}
}

// TestGrepCaseFold ci 开关（实现为 (?i) 前缀）与 pattern 原样回显。
func TestGrepCaseFold(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "cfg.ini")
	content := "SecretToken=xyz\nplain line\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	h := grepHandler(Deps{StartTime: time.Now()})

	// 默认区分大小写：不命中
	code, body := doGet(t, h, grepTarget(p, "secrettoken"))
	if code != http.StatusOK || dataOf(t, body)["matched"] != float64(0) {
		t.Fatalf("默认大小写敏感期望 0 命中: code=%d body=%v", code, body)
	}

	// ci=true：命中且回显原始 pattern（不是 (?i) 实现形态）
	code, body = doGet(t, h, grepTarget(p, "secrettoken", "ci=true"))
	if code != http.StatusOK {
		t.Fatalf("ci=true 期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if d["matched"] != float64(1) || d["pattern"] != "secrettoken" {
		t.Errorf("ci=true 不符: %v", d)
	}
	items := grepItems(t, d)
	if len(items) != 1 || items[0].LineNo != 1 || items[0].Line != "SecretToken=xyz" {
		t.Errorf("ci 命中内容不符: %+v", items)
	}
}

// TestGrepMaxStop max 截断：到数即停（scanned_bytes 不再前进）、truncated
// 保持 false（上限是调用方要的，与 /fs/search 口径一致）、越界钳制。
func TestGrepMaxStop(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "many.log")
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, fmt.Sprintf("hit-%02d", i))
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	h := grepHandler(Deps{StartTime: time.Now()})

	code, body := doGet(t, h, grepTarget(p, "hit-", "max=2"))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if d["matched"] != float64(2) || d["truncated"] != false {
		t.Fatalf("max=2 期望 matched=2 truncated=false: %v", d)
	}
	if sb, ok := d["scanned_bytes"].(float64); !ok || int64(sb) != 14 { // 2 行 × 7 字节，第 3 行起不再消费
		t.Errorf("到 max 即停：scanned_bytes 期望 14 实得 %v", d["scanned_bytes"])
	}
	items := grepItems(t, d)
	if len(items) != 2 || items[0].LineNo != 1 || items[1].LineNo != 2 {
		t.Fatalf("命中的应是最前两行: %+v", items)
	}

	// max=0 钳到 1；max=999 钳到 50（只有 10 行，实发 10）
	_, body = mustOK(t, h, grepTarget(p, "hit-", "max=0"))
	if dataOf(t, body)["matched"] != float64(1) {
		t.Errorf("max=0 应钳到 1: %v", dataOf(t, body)["matched"])
	}
	_, body = mustOK(t, h, grepTarget(p, "hit-", "max=999"))
	if dataOf(t, body)["matched"] != float64(10) {
		t.Errorf("max=999 应钳到 50（实发 10）: %v", dataOf(t, body)["matched"])
	}
}

// TestGrepValidation 参数校验：pattern 必填/非法/超长 → 400 带原因；目录
// → 400；不存在 → 404（与 /fs/read 同语义）。
func TestGrepValidation(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "a.log")
	if err := os.WriteFile(file, []byte("hello world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := grepHandler(Deps{StartTime: time.Now()})

	// pattern 必填
	code, _ := doGet(t, h, "/fs/grep?path="+url.QueryEscape(file))
	if code != http.StatusBadRequest {
		t.Errorf("缺 pattern 期望 400 实得 %d", code)
	}
	// 非法正则 → 400 带原因
	code, body := doGet(t, h, grepTarget(file, "(unclosed"))
	if code != http.StatusBadRequest {
		t.Errorf("非法正则期望 400 实得 %d", code)
	}
	if msg := errMsg(t, body); !strings.Contains(msg, "正则") {
		t.Errorf("400 文案应带正则原因: %v", body)
	}
	// 超长 pattern（201 字符）→ 400
	code, _ = doGet(t, h, grepTarget(file, strings.Repeat("a", 201)))
	if code != http.StatusBadRequest {
		t.Errorf("超长 pattern 期望 400 实得 %d", code)
	}
	// 相对路径 → 400（validateFSPath）
	code, _ = doGet(t, h, grepTarget("Windows", "x"))
	if code != http.StatusBadRequest {
		t.Errorf("相对路径期望 400 实得 %d", code)
	}
	// 目录 → 400
	code, _ = doGet(t, h, grepTarget(root, "x"))
	if code != http.StatusBadRequest {
		t.Errorf("目录期望 400 实得 %d", code)
	}
	// 不存在 → 404
	code, _ = doGet(t, h, grepTarget(filepath.Join(root, "nope.log"), "x"))
	if code != http.StatusNotFound {
		t.Errorf("不存在文件期望 404 实得 %d", code)
	}
}

// TestGrepBinary 二进制拒绝（NUL 判定）：窗口内含 NUL → 200 is_binary 带指路
// note；NUL 在 512B 嗅探窗口之外不触发——仍是文本扫描路径。
func TestGrepBinary(t *testing.T) {
	root := t.TempDir()
	h := grepHandler(Deps{StartTime: time.Now()})

	// 窗口内 NUL：拒绝且不报错（"这是二进制"本身是调查结论）
	bin := filepath.Join(root, "blob.bin")
	data := append([]byte("MZ"), make([]byte, 100)...) // 全零段必含 NUL
	if err := os.WriteFile(bin, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, body := doGet(t, h, grepTarget(bin, "anything"))
	if code != http.StatusOK {
		t.Fatalf("二进制期望 200（不报错）实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["is_binary"] != true || d["matched"] != float64(0) {
		t.Errorf("is_binary 口径不符: %v", d)
	}
	if note, _ := d["note"].(string); !strings.Contains(note, "/analyze") || !strings.Contains(note, "/fs/hash") {
		t.Errorf("note 应指路 /analyze 与 /fs/hash: %v", d["note"])
	}

	// NUL 在 600 字节处（窗口外）：不走拒绝分支，needle 照常命中
	tail := filepath.Join(root, "late-nul.log")
	content := strings.Repeat("a", 600) + "\x00needle\n"
	if err := os.WriteFile(tail, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body = doGet(t, h, grepTarget(tail, "needle"))
	if code != http.StatusOK {
		t.Fatalf("窗口外 NUL 期望 200 实得 %d", code)
	}
	d = dataOf(t, body)
	if _, ok := d["is_binary"]; ok {
		t.Errorf("窗口外 NUL 不应判二进制: %v", d)
	}
	if d["matched"] != float64(1) {
		t.Errorf("窗口外 NUL 仍应按文本扫描命中: %v", d["matched"])
	}
}

// TestGrepOverlongLine 超长行（>1MB 保留上限）：不 panic、needle 落在 1MB
// 之外被丢弃（诚实取舍）、后续行继续扫（Scanner 语义做不到的"截断继续"）、
// 偏移不受超长行影响。预算注入放大到 8MB 以免字节预算先触发。
func TestGrepOverlongLine(t *testing.T) {
	old := grepMaxScanBytes
	grepMaxScanBytes = 8 << 20
	defer func() { grepMaxScanBytes = old }()

	root := t.TempDir()
	p := filepath.Join(root, "huge.log")
	line1 := "start needle here"
	line2 := strings.Repeat("x", 1<<20) + "tail-needle" // needle 在 1MB 保留窗之外
	line3 := "third needle"
	content := line1 + "\n" + line2 + "\n" + line3 + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := grepHandler(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, grepTarget(p, "needle"))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["truncated"] != false || d["matched"] != float64(2) {
		t.Fatalf("期望 2 命中无截断: %v", d)
	}
	if sb, ok := d["scanned_bytes"].(float64); !ok || int64(sb) != int64(len(content)) {
		t.Errorf("超长行只影响保留不影响消费计数：scanned_bytes 期望 %d 实得 %v", len(content), d["scanned_bytes"])
	}
	items := grepItems(t, d)
	if len(items) != 2 {
		t.Fatalf("期望 2 条实得 %+v", items)
	}
	if items[0].LineNo != 1 || items[0].Line != line1 {
		t.Errorf("命中 1 不符: %+v", items[0])
	}
	// line2 的 needle 超出 1MB 保留窗，必须被丢弃（不是命中）
	if items[1].LineNo != 3 || items[1].Line != line3 {
		t.Fatalf("命中 2 应为第 3 行: %+v", items[1])
	}
	if want := int64(len(line1) + 1 + len(line2) + 1); items[1].Offset != want {
		t.Errorf("命中 2 offset 期望 %d 实得 %d（超长行不得扰偏移）", want, items[1].Offset)
	}
}

// TestGrepTruncatedByBytes 注入极小字节预算（真造 2MB+ 文件太慢）：触顶后
// truncated=true、预算之后的命中不出现。
func TestGrepTruncatedByBytes(t *testing.T) {
	old := grepMaxScanBytes
	grepMaxScanBytes = 16
	defer func() { grepMaxScanBytes = old }()

	root := t.TempDir()
	p := filepath.Join(root, "big.log")
	content := strings.Repeat("a", 200*1024) + "\nneedle\n" // needle 在预算之后
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := grepHandler(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, grepTarget(p, "needle"))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if d["truncated"] != true {
		t.Fatalf("预算触顶应 truncated=true: %v", d)
	}
	if d["matched"] != float64(0) {
		t.Errorf("预算之后的命中不应出现: %v", d["matched"])
	}
	// 检查粒度是块（32KB）：实扫应落在 [预算, 预算+粒度余量] 内
	if sb, ok := d["scanned_bytes"].(float64); !ok || sb < 16 || sb > 128*1024 {
		t.Errorf("scanned_bytes 应停在预算附近: %v", d["scanned_bytes"])
	}
}

// TestGrepTruncatedByTime 注入已过期时间预算（先例同 search_test.go 负预算：
// WithTimeout 对 dur<=0 同步取消，不依赖定时器调度）。行数须超过 1000 行
// 节流窗——时间预算检查按窗节流，文件太小时预算从未成为约束。
func TestGrepTruncatedByTime(t *testing.T) {
	old := grepBudget
	grepBudget = -time.Nanosecond
	defer func() { grepBudget = old }()

	root := t.TempDir()
	p := filepath.Join(root, "lines.log")
	content := strings.Repeat("x\n", 2000)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	h := grepHandler(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, grepTarget(p, "needle"))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if d["truncated"] != true || d["matched"] != float64(0) {
		t.Fatalf("时间预算触顶应 truncated=true matched=0: %v", d)
	}
}

// TestGrepEmpty 空文件：matched=0、scanned_bytes=0，且 `^`/`.*` 这类匹配
// 空串的模式不会凭空造出幽灵行。
func TestGrepEmpty(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "empty.log")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h := grepHandler(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, grepTarget(p, "^"))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	d := dataOf(t, body)
	if d["matched"] != float64(0) || d["truncated"] != false {
		t.Fatalf("空文件期望 0 命中: %v", d)
	}
	if sb, ok := d["scanned_bytes"].(float64); !ok || sb != 0 {
		t.Errorf("空文件 scanned_bytes 期望 0 实得 %v", d["scanned_bytes"])
	}
}

// errFS 读出 prefix 字节后报错的桩（真实文件造不出中途读失败）：
// 验证读错误降级为 truncated 而非 500，且已读部分的命中保留。
type errFS struct{ prefix []byte }

func (errFS) List(string) ([]Entry, error) { return nil, ErrNotDir }
func (f errFS) Stat(string) (Entry, error) {
	return Entry{Name: "e.log", Size: int64(len(f.prefix) + 4096)}, nil // size 故意与实读不符
}
func (f errFS) Open(string) (io.ReadCloser, int64, error) {
	return io.NopCloser(errReader{r: bytes.NewReader(f.prefix)}), int64(len(f.prefix) + 4096), nil
}

// errReader 底层读尽后返回非 EOF 错误（EOF 会被 bufio 归为正常行尾，
// 起不到模拟 I/O 故障的作用）。
type errReader struct{ r *bytes.Reader }

func (e errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		return n, errors.New("boom: 模拟读取失败")
	}
	return n, err
}

func TestGrepReadErrorDegraded(t *testing.T) {
	h := grepHandler(Deps{StartTime: time.Now(), FS: errFS{prefix: []byte("needle in readable part\nrest gone")}})
	code, body := doGet(t, h, grepTarget(`C:\e.log`, "needle"))
	if code != http.StatusOK {
		t.Fatalf("读错误应降级 200 而非 500 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["truncated"] != true {
		t.Fatalf("读错误应 truncated=true: %v", d)
	}
	if d["matched"] != float64(1) {
		t.Errorf("已读部分的命中应保留: %v", d["matched"])
	}
	items := grepItems(t, d)
	if len(items) != 1 || items[0].LineNo != 1 {
		t.Errorf("命中行不符: %+v", items)
	}
}
