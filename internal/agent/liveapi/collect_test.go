//go:build windows
// +build windows

package liveapi

// collect_test.go：/collect 端点。FS 一律用内存桩（memFS）注入——
// 截断分支（64MB 单文件 / 128MB 总预算 / 流中触顶）造不出真文件，
// 且桩可精确编程"Stat 报小、内容很大""读一半坏掉"这类 TOCTOU 形态。
//
// 路由注册归主线会话所有（liveapi.go），这里自建 mux 直挂 handleCollect；
// 主线把 "GET /collect" 加进 New() 后行为等价（recoverWrap 对正常路径透明）。
// 预算变量为包级可注入（模式同 searchBudget），本文件全部串行运行、
// 注入后 defer 恢复，不与套件内其他测试并发冲突。

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- 内存 FS 桩 ----

// memNode 是 memFS 的单节点；statSize>0 时 Stat 谎报大小——模拟"Stat 与
// Open 之间文件变大"（流中触顶分支的差异造不出真 128MB，只能谎报）。
type memNode struct {
	content  []byte
	isDir    bool
	mtime    time.Time
	statSize int64
}

// memFS 是 FSys 的内存实现：内容、失败点全部可编程。
// /collect 只消费 Stat/Open，List 恒返 ErrNotDir（无消费方）。
type memFS struct {
	files     map[string]*memNode
	errOpen   map[string]error // Open 直失败（模拟 Stat 后 TOCTOU 删除/权限收紧）
	errAfterN map[string]int64 // 读满 N 字节后报错（模拟介质错/半路读断）
}

var errSimulatedRead = errors.New("memfs: simulated mid-stream read failure")

func newMemFS() *memFS {
	return &memFS{
		files:     map[string]*memNode{},
		errOpen:   map[string]error{},
		errAfterN: map[string]int64{},
	}
}

func (m *memFS) add(path string, content []byte) {
	m.files[path] = &memNode{content: content, mtime: time.Unix(1700000000, 0).UTC()}
}

func (m *memFS) addDir(path string) {
	m.files[path] = &memNode{isDir: true, mtime: time.Unix(1700000000, 0).UTC()}
}

func (m *memFS) List(dir string) ([]Entry, error) { return nil, ErrNotDir }

func (m *memFS) Stat(path string) (Entry, error) {
	n, ok := m.files[path]
	if !ok {
		return Entry{}, ErrNotExist
	}
	size := int64(len(n.content))
	if n.statSize > 0 {
		size = n.statSize
	}
	return Entry{Name: filepath.Base(path), Size: size, IsDir: n.isDir, MtimeUnix: n.mtime.Unix()}, nil
}

func (m *memFS) Open(path string) (io.ReadCloser, int64, error) {
	if err, ok := m.errOpen[path]; ok {
		return nil, 0, err
	}
	n, ok := m.files[path]
	if !ok {
		return nil, 0, ErrNotExist
	}
	if n.isDir {
		return nil, 0, ErrIsDir
	}
	var r io.ReadCloser = io.NopCloser(bytes.NewReader(n.content))
	if after, ok := m.errAfterN[path]; ok {
		r = &errAfterNReader{r: r, after: after}
	}
	return r, int64(len(n.content)), nil
}

// errAfterNReader 读满 after 字节后持续报错；每次 Read 至多给 1 字节，
// 确保"部分内容"真的部分（bytes.Reader 会一口气吐完，测不出半条目）。
type errAfterNReader struct {
	r     io.ReadCloser
	after int64
	read  int64
}

func (e *errAfterNReader) Read(p []byte) (int, error) {
	if e.read >= e.after {
		return 0, errSimulatedRead
	}
	if int64(len(p)) > e.after-e.read {
		p = p[:e.after-e.read]
	}
	n, err := e.r.Read(p)
	e.read += int64(n)
	return n, err
}

func (e *errAfterNReader) Close() error { return e.r.Close() }

// ---- 夹具 helper ----

func collectHandler(d Deps) http.Handler {
	if d.FS == nil {
		d.FS = OSFS{}
	}
	s := &server{d: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /collect", s.handleCollect)
	return mux
}

func collectQuery(paths ...string) string {
	var b strings.Builder
	b.WriteString("/collect")
	for i, p := range paths {
		if i == 0 {
			b.WriteString("?p=")
		} else {
			b.WriteString("&p=")
		}
		b.WriteString(url.QueryEscape(p))
	}
	return b.String()
}

// readZipManifest 解开响应 zip：返回 manifest、条目名→内容、条目元数据。
// 能走通本身就证明 central directory 完整（Close 补齐未被截断破坏）。
func readZipManifest(t *testing.T, body []byte) (*collectManifest, map[string][]byte, []*zip.File) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("响应不是合法 zip: %v", err)
	}
	contents := map[string][]byte{}
	var mf collectManifest
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("打开条目 %s 失败: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("读取条目 %s 失败: %v", f.Name, err)
		}
		contents[f.Name] = b
		if f.Name == manifestName {
			if err := json.Unmarshal(b, &mf); err != nil {
				t.Fatalf("manifest 不是合法 JSON: %v body=%s", err, b)
			}
		}
	}
	return &mf, contents, zr.File
}

func findEntry(files []*zip.File, name string) *zip.File {
	for _, f := range files {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// ---- 用例 ----

// TestCollectBasic 三文件（文本/二进制/多行日志）→ zip 可解、条目数=4、
// manifest sha256 与本地直算一致、内容逐字节一致、条目 mtime 透传。
func TestCollectBasic(t *testing.T) {
	fs := newMemFS()
	a := []byte("alpha content")
	b := []byte{0x00, 0x01, 0x02, 0xFE, 0xFF}
	c := bytes.Repeat([]byte("log line\n"), 100)
	fs.add(`C:\ev\a.txt`, a)
	fs.add(`C:\ev\b.bin`, b)
	fs.add(`C:\other\c.log`, c)
	h := collectHandler(Deps{Version: "9.9.9-test", FS: fs})

	rec := doRaw(t, h, collectQuery(`C:\ev\a.txt`, `C:\ev\b.bin`, `C:\other\c.log`))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type 期望 application/zip 实得 %q", ct)
	}
	if cf := rec.Header().Get("X-ZEDR-Collect-Files"); cf != "3" {
		t.Errorf("X-ZEDR-Collect-Files 期望 3 实得 %q", cf)
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "0" {
		t.Errorf("未截断期望 X-ZEDR-Truncated=0 实得 %q", tr)
	}

	mf, contents, entries := readZipManifest(t, rec.Body.Bytes())
	if mf.AgentVersion != "9.9.9-test" {
		t.Errorf("agent_version 不符: %q", mf.AgentVersion)
	}
	if mf.CollectedAt <= 0 {
		t.Errorf("collected_at 应为 unix 秒: %d", mf.CollectedAt)
	}
	if mf.Truncated {
		t.Error("正常完成 truncated 应为 false")
	}
	if len(mf.Files) != 3 || len(mf.Errors) != 0 {
		t.Fatalf("manifest 应 3 files / 0 errors: %+v", mf)
	}
	if len(contents) != 4 {
		t.Fatalf("zip 条目数期望 4（3 文件+manifest）实得 %d: %v", len(contents), contents)
	}

	for i, want := range []struct {
		path string
		data []byte
	}{
		{`C:\ev\a.txt`, a}, {`C:\ev\b.bin`, b}, {`C:\other\c.log`, c},
	} {
		got := mf.Files[i]
		if got.Path != want.path {
			t.Errorf("files[%d].path 期望 %q 实得 %q", i, want.path, got.Path)
		}
		zipName := fmt.Sprintf("%04d_%s", i+1, filepath.Base(want.path))
		if got.ZipName != zipName {
			t.Errorf("zip_name 期望 %q 实得 %q", zipName, got.ZipName)
		}
		sum := sha256.Sum256(want.data)
		if got.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("sha256 与本地直算不符: %s", got.ZipName)
		}
		if got.Size != int64(len(want.data)) {
			t.Errorf("size 期望 %d 实得 %d", len(want.data), got.Size)
		}
		content, ok := contents[zipName]
		if !ok {
			t.Fatalf("zip 缺条目 %s（实有 %v）", zipName, contents)
		}
		if !bytes.Equal(content, want.data) {
			t.Errorf("内容逐字节不一致: %s", zipName)
		}
		if e := findEntry(entries, zipName); e == nil || e.Modified.Unix() != 1700000000 {
			t.Errorf("条目 %s Modified 应透传文件 mtime: %v", zipName, e)
		}
	}
}

// TestCollectParamValidation 参数面：缺参/非法路径/超量 → 400；去重
// （完全同名 + 大小写不敏感同名）→ 单条目。
func TestCollectParamValidation(t *testing.T) {
	fs := newMemFS()
	h := collectHandler(Deps{FS: fs})

	// 缺参
	if code, _ := doGet(t, h, "/collect"); code != http.StatusBadRequest {
		t.Errorf("缺 p 期望 400 实得 %d", code)
	}
	// 非法路径（validateFSPath 的表驱动在 fs_test.go 已覆盖，这里抽两笔
	// 证明 /collect 走同一道校验，且 16 个合法 + 1 个非法也整体 400）
	for _, tc := range []struct {
		name string
		p    []string
	}{
		{"上跳", []string{`C:\ok\a.txt`, `C:\Windows\..\x`}},
		{"相对路径", []string{`Windows`}},
		{"超量", func() []string {
			ps := make([]string, collectMaxPaths+1)
			for i := range ps {
				ps[i] = fmt.Sprintf(`C:\x\f%02d.bin`, i)
			}
			return ps
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := doGet(t, h, collectQuery(tc.p...)); code != http.StatusBadRequest {
				t.Errorf("期望 400 实得 %d", code)
			}
		})
	}

	// 16 个合法（边界内放行）
	for i := 0; i < collectMaxPaths; i++ {
		fs.add(fmt.Sprintf(`C:\m\f%02d.txt`, i), []byte("x"))
	}
	rec := doRaw(t, h, collectQuery(func() []string {
		ps := make([]string, collectMaxPaths)
		for i := range ps {
			ps[i] = fmt.Sprintf(`C:\m\f%02d.txt`, i)
		}
		return ps
	}()...))
	if rec.Code != http.StatusOK {
		t.Fatalf("16 个合法路径期望 200 实得 %d", rec.Code)
	}
	mf, _, _ := readZipManifest(t, rec.Body.Bytes())
	if len(mf.Files) != collectMaxPaths {
		t.Errorf("期望 %d 个文件实得 %d", collectMaxPaths, len(mf.Files))
	}

	// 去重：完全同名 + casefold 同名（Windows 路径大小写不敏感）
	fs2 := newMemFS()
	fs2.add(`C:\ev\a.txt`, []byte("dup"))
	h2 := collectHandler(Deps{FS: fs2})
	rec = doRaw(t, h2, collectQuery(`C:\ev\a.txt`, `C:\ev\a.txt`, `C:\EV\A.TXT`))
	if rec.Code != http.StatusOK {
		t.Fatalf("去重请求失败: %d", rec.Code)
	}
	mf, _, _ = readZipManifest(t, rec.Body.Bytes())
	if len(mf.Files) != 1 || len(mf.Errors) != 0 {
		t.Fatalf("重名应去重为 1 条: files=%d errors=%d", len(mf.Files), len(mf.Errors))
	}
	if mf.Files[0].Path != `C:\ev\a.txt` {
		t.Errorf("去重应保序取首个: %q", mf.Files[0].Path)
	}
}

// TestCollectPartialMissing 1 存在 + 1 不存在 → 200 流式 + errors 含不存在项；
// 全不存在 → 404（不开空 zip 流）。
func TestCollectPartialMissing(t *testing.T) {
	fs := newMemFS()
	fs.add(`C:\ok.txt`, []byte("ok"))
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(`C:\ok.txt`, `C:\gone.txt`))
	if rec.Code != http.StatusOK {
		t.Fatalf("部分合法期望 200 实得 %d body=%s", rec.Code, rec.Body.String())
	}
	if cf := rec.Header().Get("X-ZEDR-Collect-Files"); cf != "1" {
		t.Errorf("X-ZEDR-Collect-Files 期望 1 实得 %q", cf)
	}
	mf, contents, _ := readZipManifest(t, rec.Body.Bytes())
	if len(mf.Files) != 1 || mf.Files[0].Path != `C:\ok.txt` {
		t.Fatalf("files 应只含存在文件: %+v", mf.Files)
	}
	if !bytes.Equal(contents[mf.Files[0].ZipName], []byte("ok")) {
		t.Error("存在文件内容不一致")
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != `C:\gone.txt` || mf.Errors[0].Error != "not_found" {
		t.Fatalf("errors 应含 gone.txt(not_found): %+v", mf.Errors)
	}
	if mf.Errors[0].SHA256 != nil {
		t.Errorf("失败项 sha256 应为 null: %v", mf.Errors[0].SHA256)
	}
	if mf.Truncated {
		t.Error("缺文件不算截断，truncated 应为 false")
	}

	// 全不存在 → 404 带逐项说明
	code, body := doGet(t, h, collectQuery(`C:\nope1.txt`, `C:\nope2.txt`))
	if code != http.StatusNotFound {
		t.Fatalf("全不存在期望 404 实得 %d", code)
	}
	if msg := errMsg(t, body); !strings.Contains(msg, "没有可采集的文件") || !strings.Contains(msg, "not_found") {
		t.Errorf("404 文案缺说明: %q", msg)
	}
}

// TestCollectDirPath 目录 → errors 而非 500；仅目录（无任何可采集）→
// 400 带说明，不开流。
func TestCollectDirPath(t *testing.T) {
	fs := newMemFS()
	fs.addDir(`C:\data\dir`)
	fs.add(`C:\data\f.txt`, []byte("f"))
	h := collectHandler(Deps{FS: fs})

	// 目录混在合法清单里 → 200 + errors(is_directory)
	rec := doRaw(t, h, collectQuery(`C:\data\dir`, `C:\data\f.txt`))
	if rec.Code != http.StatusOK {
		t.Fatalf("目录+文件期望 200 实得 %d body=%s", rec.Code, rec.Body.String())
	}
	mf, contents, _ := readZipManifest(t, rec.Body.Bytes())
	if len(mf.Files) != 1 || mf.Files[0].Path != `C:\data\f.txt` || !bytes.Equal(contents[mf.Files[0].ZipName], []byte("f")) {
		t.Fatalf("文件应照常采集: %+v", mf.Files)
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != `C:\data\dir` || mf.Errors[0].Error != "is_directory" {
		t.Fatalf("目录应进 errors(is_directory): %+v", mf.Errors)
	}

	// 只有目录 → 400 带说明（计划为空时绝不能 500）
	code, body := doGet(t, h, collectQuery(`C:\data\dir`))
	if code != http.StatusBadRequest {
		t.Fatalf("仅目录期望 400 实得 %d", code)
	}
	if msg := errMsg(t, body); !strings.Contains(msg, "is_directory") {
		t.Errorf("400 文案应含 is_directory: %q", msg)
	}
}

// TestCollectTooLarge 单文件 64MB 上限：超限进 errors 不中断流；全部超限
// → 400。用 statSize 谎报，不造 64MB 真内容。
func TestCollectTooLarge(t *testing.T) {
	fs := newMemFS()
	huge := `C:\ev\huge.bin`
	fs.files[huge] = &memNode{mtime: time.Unix(1700000000, 0), statSize: collectFileMaxBytes + 1}
	fs.add(`C:\ev\ok.txt`, []byte("ok"))
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(huge, `C:\ev\ok.txt`))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%s", rec.Code, rec.Body.String())
	}
	mf, _, _ := readZipManifest(t, rec.Body.Bytes())
	if len(mf.Files) != 1 || mf.Files[0].Path != `C:\ev\ok.txt` {
		t.Fatalf("ok.txt 应照常采集: %+v", mf.Files)
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != huge || mf.Errors[0].Error != "too_large" {
		t.Fatalf("huge.bin 应进 errors(too_large): %+v", mf.Errors)
	}

	// 全部超限 → 400 带说明
	code, body := doGet(t, h, collectQuery(huge))
	if code != http.StatusBadRequest {
		t.Fatalf("全部超限期望 400 实得 %d", code)
	}
	if msg := errMsg(t, body); !strings.Contains(msg, "too_large") {
		t.Errorf("400 文案应含 too_large: %q", msg)
	}
}

// TestCollectBudgetPlanSkip 注入总预算 10B：6B+8B 的第二文件在计划阶段
// 即 budget_exceeded（停止加新文件），truncated 与响应头同步为 1。
func TestCollectBudgetPlanSkip(t *testing.T) {
	old := collectTotalMaxBytes
	collectTotalMaxBytes = 10
	defer func() { collectTotalMaxBytes = old }()

	fs := newMemFS()
	fs.add(`C:\s\f1.bin`, []byte("aaaaaa"))   // 6B，进预算
	fs.add(`C:\s\f2.bin`, []byte("bbbbbbbb")) // 8B，6+8>10 → 拒收
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(`C:\s\f1.bin`, `C:\s\f2.bin`))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", rec.Code)
	}
	if cf := rec.Header().Get("X-ZEDR-Collect-Files"); cf != "1" {
		t.Errorf("Collect-Files 期望 1 实得 %q", cf)
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "1" {
		t.Errorf("预算截断期望 Truncated=1 实得 %q", tr)
	}
	mf, contents, _ := readZipManifest(t, rec.Body.Bytes())
	if !mf.Truncated {
		t.Error("manifest.truncated 应为 true")
	}
	if len(mf.Files) != 1 || mf.Files[0].Path != `C:\s\f1.bin` {
		t.Fatalf("files 应只含 f1: %+v", mf.Files)
	}
	if !bytes.Equal(contents[mf.Files[0].ZipName], []byte("aaaaaa")) {
		t.Error("f1 内容不一致")
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != `C:\s\f2.bin` || mf.Errors[0].Error != "budget_exceeded" {
		t.Fatalf("f2 应 budget_exceeded: %+v", mf.Errors)
	}
}

// TestCollectBudgetMidStream 流中触顶：Stat 报 6B（谎报）实际 20B，预算
// 10B——部分条目入 zip（结构合法），manifest 记 mid-stream 失败且 sha256=null。
func TestCollectBudgetMidStream(t *testing.T) {
	old := collectTotalMaxBytes
	collectTotalMaxBytes = 10
	defer func() { collectTotalMaxBytes = old }()

	fs := newMemFS()
	grown := `C:\g\grown.bin`
	content := bytes.Repeat([]byte{0xAB}, 20)
	fs.files[grown] = &memNode{content: content, mtime: time.Unix(1700000000, 0), statSize: 6}
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(grown))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", rec.Code)
	}
	// 头部是计划时点的可预见值：Stat 谎报 6B 在预算内，流中触顶对头部
	// 不可预见——保持 0；真正的截断状态以 manifest 为准（契约注释口径）
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "0" {
		t.Errorf("计划不可预见的流中触顶，头部应保持 0 实得 %q", tr)
	}
	mf, contents, entries := readZipManifest(t, rec.Body.Bytes())
	if !mf.Truncated {
		t.Error("manifest.truncated 应为 true")
	}
	if len(mf.Files) != 0 {
		t.Errorf("触顶文件不得计入 files: %+v", mf.Files)
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != grown || mf.Errors[0].Error != "budget_exceeded mid-stream" {
		t.Fatalf("应记 budget_exceeded mid-stream: %+v", mf.Errors)
	}
	if mf.Errors[0].SHA256 != nil {
		t.Errorf("部分内容 sha256 必须为 null: %v", mf.Errors[0].SHA256)
	}
	// 部分条目结构合法且内容为预算内前 10 字节（解压工具拿到的是截断
	// 数据而非 CRC 报错——这正是 manifest 必须是事实源的原因）
	partial, ok := contents["0001_grown.bin"]
	if !ok || len(entries) != 2 {
		t.Fatalf("zip 应含部分条目+manifest 共 2 条: %v", entries)
	}
	if !bytes.Equal(partial, content[:10]) {
		t.Errorf("部分条目应为前 10 字节: len=%d", len(partial))
	}
}

// TestCollectReadFailure 读一半坏掉 → read_failed mid-stream（sha256=null），
// 后续文件不受影响继续采集；读失败不算截断（truncated=false）。
func TestCollectReadFailure(t *testing.T) {
	fs := newMemFS()
	fs.add(`C:\r\bad.bin`, []byte("0123456789"))
	fs.errAfterN[`C:\r\bad.bin`] = 3
	fs.add(`C:\r\good.bin`, []byte("good"))
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(`C:\r\bad.bin`, `C:\r\good.bin`))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", rec.Code)
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "0" {
		t.Errorf("读失败不算截断，期望 Truncated=0 实得 %q", tr)
	}
	mf, contents, entries := readZipManifest(t, rec.Body.Bytes())
	if mf.Truncated {
		t.Error("manifest.truncated 应为 false")
	}
	if len(mf.Files) != 1 || mf.Files[0].Path != `C:\r\good.bin` {
		t.Fatalf("good.bin 应照常采集: %+v", mf.Files)
	}
	if !bytes.Equal(contents[mf.Files[0].ZipName], []byte("good")) {
		t.Error("good.bin 内容不一致")
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != `C:\r\bad.bin` || mf.Errors[0].Error != "read_failed mid-stream" {
		t.Fatalf("bad.bin 应记 read_failed mid-stream: %+v", mf.Errors)
	}
	if mf.Errors[0].SHA256 != nil {
		t.Errorf("失败项 sha256 应为 null: %v", mf.Errors[0].SHA256)
	}
	// 部分条目内容 = 读到的 3 字节（zip 里存在但 manifest 判其不可信）
	if p := contents["0001_bad.bin"]; !bytes.Equal(p, []byte("012")) {
		t.Errorf("部分条目应为 3 字节 '012': %q", p)
	}
	if len(entries) != 3 {
		t.Errorf("zip 条目数期望 3（2 部分文件+manifest）实得 %d", len(entries))
	}
}

// TestCollectOpenFail Stat 正常但 Open 失败（TOCTOU）→ open_failed，
// 其余文件照常。
func TestCollectOpenFail(t *testing.T) {
	fs := newMemFS()
	fs.add(`C:\o\ghost.txt`, []byte("x"))
	fs.errOpen[`C:\o\ghost.txt`] = ErrPermission
	fs.add(`C:\o\ok.txt`, []byte("ok"))
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(`C:\o\ghost.txt`, `C:\o\ok.txt`))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", rec.Code)
	}
	mf, _, _ := readZipManifest(t, rec.Body.Bytes())
	if len(mf.Files) != 1 || mf.Files[0].Path != `C:\o\ok.txt` {
		t.Fatalf("ok.txt 应照常采集: %+v", mf.Files)
	}
	if len(mf.Errors) != 1 || mf.Errors[0].Path != `C:\o\ghost.txt` || !strings.HasPrefix(mf.Errors[0].Error, "open_failed") {
		t.Fatalf("ghost 应记 open_failed: %+v", mf.Errors)
	}
}

// TestCollectDeadline 注入已过期软预算：所有计划文件 deadline_exceeded，
// 仍产出合法 zip（只有 manifest），响应头同步 Truncated=1。
func TestCollectDeadline(t *testing.T) {
	old := collectSoftDeadline
	collectSoftDeadline = -time.Nanosecond
	defer func() { collectSoftDeadline = old }()

	fs := newMemFS()
	fs.add(`C:\d\f1.txt`, []byte("1"))
	fs.add(`C:\d\f2.txt`, []byte("2"))
	h := collectHandler(Deps{FS: fs})

	rec := doRaw(t, h, collectQuery(`C:\d\f1.txt`, `C:\d\f2.txt`))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", rec.Code)
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "1" {
		t.Errorf("超期期望 Truncated=1 实得 %q", tr)
	}
	mf, _, entries := readZipManifest(t, rec.Body.Bytes())
	if !mf.Truncated {
		t.Error("manifest.truncated 应为 true")
	}
	if len(mf.Files) != 0 {
		t.Errorf("超期后不得有 files: %+v", mf.Files)
	}
	if len(mf.Errors) != 2 {
		t.Fatalf("两个文件都应进 errors: %+v", mf.Errors)
	}
	for _, e := range mf.Errors {
		if e.Error != "deadline_exceeded" {
			t.Errorf("期望 deadline_exceeded: %+v", e)
		}
	}
	if len(entries) != 1 {
		t.Errorf("zip 应只有 manifest 条目: %v", entries)
	}
}
