package liveapi

// fs_test.go：/fs、/fs/stat、/fs/read、/fs/hash 端点 + 路径校验表驱动。
// 一律 httptest 直打 New() handler + t.TempDir 真实文件系统。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPathValidation 契约 §5.2 逐条的表驱动：全部 400，并用真实临时目录对拍放行。
func TestPathValidation(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	cases := []struct{ name, path string }{
		{"盘符相对-反斜杠", `\foo`},
		{"盘符相对-带盘号", `C:foo`},
		{"上跳一段", `C:\Windows\..\Elsewhere`},
		{"上跳多段", `C:\Windows\..\..\Windows`},
		{"纯上跳", `C:\..`},
		{"正斜杠上跳", `C:/../x`},
		{"设备命名空间", `\\.\PhysicalDrive0`},
		{"长路径前缀", `\\?\C:\Windows`},
		{"相对路径", `Windows`},
		{"空 path", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := doGet(t, h, "/fs/stat?path="+url.QueryEscape(tc.path))
			if code != http.StatusBadRequest {
				t.Fatalf("path=%q 期望 400 实得 %d body=%v", tc.path, code, body)
			}
		})
	}

	// 对拍：真实存在的临时目录应放行（保证表驱动没有"全拒"假阳性）
	tmp := t.TempDir()
	if code, body := doGet(t, h, "/fs/stat?path="+url.QueryEscape(tmp)); code != http.StatusOK {
		t.Fatalf("合法路径 %q 期望 200 实得 %d body=%v", tmp, code, body)
	}
}

func TestFSListPagination(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "many")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	const total = 450
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("f%04d.txt", i)
		if err := os.WriteFile(filepath.Join(sub, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := New(Deps{StartTime: time.Now()})

	// 第一页：默认 limit=200，next_cursor=o200
	code, body := doGet(t, h, "/fs?path="+url.QueryEscape(sub))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if d["path"] != filepath.Clean(sub) {
		t.Errorf("path 回显不符: %v", d["path"])
	}
	if entries := d["entries"].([]any); len(entries) != fsListDefault {
		t.Fatalf("默认页大小期望 %d 实得 %d", fsListDefault, len(entries))
	}
	if next := d["next_cursor"]; next != "o200" {
		t.Fatalf("next_cursor 期望 o200 实得 %v", next)
	}

	// 翻页到结尾：不重不漏，3 页收敛
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		target := "/fs?path=" + url.QueryEscape(sub)
		if cursor != "" {
			target += "&cursor=" + url.QueryEscape(cursor)
		}
		code, body := doGet(t, h, target)
		if code != http.StatusOK {
			t.Fatalf("翻页请求失败 cursor=%q code=%d", cursor, code)
		}
		d := dataOf(t, body)
		for _, e := range d["entries"].([]any) {
			name := e.(map[string]any)["name"].(string)
			if seen[name] {
				t.Fatalf("条目重复: %s", name)
			}
			seen[name] = true
		}
		cursor, _ = d["next_cursor"].(string)
		pages++
		if cursor == "" {
			break
		}
		if pages > 10 {
			t.Fatal("翻页不收敛")
		}
	}
	if len(seen) != total {
		t.Fatalf("总条目期望 %d 实得 %d", total, len(seen))
	}
	if pages != 3 {
		t.Fatalf("期望 3 页实得 %d", pages)
	}

	// limit 上限钳制 500（目录只有 total 个文件，钳到 500 后实发 total 条）
	code, body = doGet(t, h, "/fs?path="+url.QueryEscape(sub)+"&limit=9999")
	if code != http.StatusOK {
		t.Fatalf("钳制请求失败: %d", code)
	}
	if entries := dataOf(t, body)["entries"].([]any); len(entries) != total {
		t.Fatalf("limit=9999 期望实发 %d 条实得 %d", total, len(entries))
	}

	// 非法 cursor → 400
	for _, bad := range []string{"x9", "o", "o-1", "o99999999999999999999"} {
		code, _ := doGet(t, h, "/fs?path="+url.QueryEscape(sub)+"&cursor="+url.QueryEscape(bad))
		if code != http.StatusBadRequest {
			t.Fatalf("cursor=%q 期望 400 实得 %d", bad, code)
		}
	}

	// 目标是文件 / 不存在
	file := filepath.Join(root, "plain.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := doGet(t, h, "/fs?path="+url.QueryEscape(file)); code != http.StatusBadRequest {
		t.Fatalf("对文件列目录期望 400 实得 %d", code)
	}
	if code, _ := doGet(t, h, "/fs?path="+url.QueryEscape(filepath.Join(root, "nope"))); code != http.StatusNotFound {
		t.Fatalf("列不存在目录期望 404 实得 %d", code)
	}
}

// TestFSListSortDirsFirst 目录优先 + casefold 升序 + Entry 字段名逐字对齐契约。
func TestFSListSortDirsFirst(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"zdir", "adir"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"m.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("hi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/fs?path="+url.QueryEscape(root))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	raw, err := json.Marshal(dataOf(t, body)["entries"])
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Name      string `json:"name"`
		Size      int64  `json:"size"`
		IsDir     bool   `json:"is_dir"`
		Hidden    bool   `json:"hidden"`
		System    bool   `json:"system"`
		Readonly  bool   `json:"readonly"`
		Reparse   bool   `json:"reparse"`
		MtimeUnix int64  `json:"mtime_unix"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("Entry 字段名与契约不符: %v raw=%s", err, raw)
	}
	want := []string{"adir", "zdir", "b.txt", "m.txt"}
	for i, e := range entries {
		if e.Name != want[i] {
			t.Fatalf("排序不符: 位置 %d 期望 %s 实得 %s", i, want[i], e.Name)
		}
	}
	if !entries[0].IsDir || !entries[1].IsDir || entries[2].IsDir || entries[3].IsDir {
		t.Fatalf("目录应排在前: %+v", entries)
	}
	if entries[2].Size != 2 || entries[2].MtimeUnix <= 0 {
		t.Errorf("size/mtime_unix 不符: %+v", entries[2])
	}
}

// TestHiddenAttr Windows 下 attrib +h 验证 hidden:true（覆盖 fileattr.go）。
func TestHiddenAttr(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("属性位仅 Windows 有意义")
	}
	root := t.TempDir()
	plain := filepath.Join(root, "plain.txt")
	hidden := filepath.Join(root, "hidden.txt")
	if err := os.WriteFile(plain, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hidden, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("attrib", "+h", hidden).Run(); err != nil {
		t.Fatalf("attrib +h 失败: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("attrib", "-h", hidden).Run() })

	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/fs?path="+url.QueryEscape(root))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d", code)
	}
	hiddenSeen := false
	for _, e := range dataOf(t, body)["entries"].([]any) {
		m := e.(map[string]any)
		switch m["name"] {
		case "hidden.txt":
			hiddenSeen = true
			if m["hidden"] != true {
				t.Errorf("hidden.txt 期望 hidden:true: %v", m)
			}
		case "plain.txt":
			if m["hidden"] != false {
				t.Errorf("plain.txt 期望 hidden:false: %v", m)
			}
		}
	}
	if !hiddenSeen {
		t.Fatal("列表中未找到 hidden.txt")
	}

	// stat 口径一致
	_, sbody := mustOK(t, h, "/fs/stat?path="+url.QueryEscape(hidden))
	d := dataOf(t, sbody)
	if d["hidden"] != true || d["exists"] != true {
		t.Errorf("stat hidden 不符: %v", d)
	}
}

func mustOK(t *testing.T, h http.Handler, target string) (int, map[string]any) {
	t.Helper()
	code, body := doGet(t, h, target)
	if code != http.StatusOK {
		t.Fatalf("%s 期望 200 实得 %d body=%v", target, code, body)
	}
	return code, body
}

func TestFSStat(t *testing.T) {
	root := t.TempDir()
	h := New(Deps{StartTime: time.Now()})

	// 不存在 → 200 exists:false（而非 404）
	_, ebody := mustOK(t, h, "/fs/stat?path="+url.QueryEscape(filepath.Join(root, "nope.bin")))
	d := dataOf(t, ebody)
	if d["exists"] != false {
		t.Errorf("不存在的路径期望 exists:false: %v", d)
	}

	// 存在的目录与文件
	dir := filepath.Join(root, "sub")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o444); err != nil {
		t.Fatal(err)
	}
	_, dbody := mustOK(t, h, "/fs/stat?path="+url.QueryEscape(dir))
	d = dataOf(t, dbody)
	if d["exists"] != true || d["is_dir"] != true {
		t.Errorf("目录 stat 不符: %v", d)
	}
	_, fbody := mustOK(t, h, "/fs/stat?path="+url.QueryEscape(file))
	d = dataOf(t, fbody)
	if d["is_dir"] != false {
		t.Errorf("文件 is_dir 应为 false: %v", d)
	}
	if sz, ok := d["size"].(float64); !ok || int64(sz) != 5 {
		t.Errorf("size 期望 5 实得 %v", d["size"])
	}
	// 只读位 → readonly:true（GetFileAttributes 直取，os.Stat 权限位不参与）
	if d["readonly"] != true {
		t.Errorf("readonly 期望 true: %v", d)
	}
	for _, k := range []string{"path", "exists", "size", "is_dir", "hidden", "system", "readonly", "reparse", "mtime_unix"} {
		if _, ok := d[k]; !ok {
			t.Errorf("stat 响应缺字段 %s（契约 §5.2）", k)
		}
	}
}

func TestFSRead(t *testing.T) {
	root := t.TempDir()
	h := New(Deps{StartTime: time.Now()})

	// 文本：嗅探 + 不双 charset + 全量头
	textPath := filepath.Join(root, "note.txt")
	content := "hello world\nsecond line\n"
	if err := os.WriteFile(textPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := doRaw(t, h, "/fs/read?path="+url.QueryEscape(textPath))
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != content {
		t.Errorf("内容不符: %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("文本嗅探期望 text/plain; charset=utf-8 实得 %q", ct)
	}
	if fs := rec.Header().Get("X-ZEDR-File-Size"); fs != strconv.Itoa(len(content)) {
		t.Errorf("X-ZEDR-File-Size 期望 %d 实得 %q", len(content), fs)
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "0" {
		t.Errorf("全量读取期望 Truncated=0 实得 %q", tr)
	}

	// 二进制：嗅探为 application/octet-stream
	binPath := filepath.Join(root, "blob.bin")
	bin := make([]byte, 64)
	for i := range bin {
		bin[i] = byte(i * 7)
	}
	bin[0] = 0x00 // 强制走二进制分支
	if err := os.WriteFile(binPath, bin, 0o644); err != nil {
		t.Fatal(err)
	}
	rec = doRaw(t, h, "/fs/read?path="+url.QueryEscape(binPath))
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("二进制嗅探期望 application/octet-stream 实得 %q", ct)
	}

	// 区间读取：offset/limit/截断头
	rec = doRaw(t, h, "/fs/read?path="+url.QueryEscape(textPath)+"&offset=2&limit=3")
	if rec.Code != http.StatusOK {
		t.Fatalf("区间读取失败: %d", rec.Code)
	}
	if got := rec.Body.String(); got != "llo" {
		t.Errorf("区间内容期望 llo 实得 %q", got)
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "1" {
		t.Errorf("区间读取期望 Truncated=1 实得 %q", tr)
	}
	if cl := rec.Header().Get("Content-Length"); cl != "3" {
		t.Errorf("Content-Length 期望 3 实得 %q", cl)
	}

	// limit 上限钳制 512KB（不整文件进内存，按 limit 截断）
	bigPath := filepath.Join(root, "big.bin")
	big := make([]byte, 600*1024)
	for i := range big {
		big[i] = byte(i)
	}
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	rec = doRaw(t, h, "/fs/read?path="+url.QueryEscape(bigPath)+"&limit=9999999")
	if rec.Code != http.StatusOK {
		t.Fatalf("钳制读取失败: %d", rec.Code)
	}
	if rec.Body.Len() != fsReadMax {
		t.Errorf("期望钳到 %d 字节实得 %d", fsReadMax, rec.Body.Len())
	}
	if tr := rec.Header().Get("X-ZEDR-Truncated"); tr != "1" {
		t.Errorf("大文件期望 Truncated=1 实得 %q", tr)
	}

	// 目录拒绝 / 越界 / 空文件
	if code, body := doGet(t, h, "/fs/read?path="+url.QueryEscape(root)); code != http.StatusBadRequest {
		t.Errorf("读目录期望 400 实得 %d body=%v", code, body)
	}
	code, body := doGet(t, h, "/fs/read?path="+url.QueryEscape(textPath)+"&offset="+strconv.Itoa(len(content)))
	if code != http.StatusBadRequest {
		t.Errorf("offset==size 期望 400 实得 %d", code)
	}
	if !strings.Contains(errMsg(t, body), "偏移超出文件大小") {
		t.Errorf("越界文案不符: %v", body)
	}
	if code, _ := doGet(t, h, "/fs/read?path="+url.QueryEscape(textPath)+"&offset=99999"); code != http.StatusBadRequest {
		t.Errorf("offset>>size 期望 400 实得 %d", code)
	}
	empty := filepath.Join(root, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rec = doRaw(t, h, "/fs/read?path="+url.QueryEscape(empty))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("空文件 offset=0 应 200 空体: code=%d len=%d", rec.Code, rec.Body.Len())
	}
	if fs := rec.Header().Get("X-ZEDR-File-Size"); fs != "0" {
		t.Errorf("空文件 X-ZEDR-File-Size 期望 0 实得 %q", fs)
	}
	if code, _ := doGet(t, h, "/fs/read?path="+url.QueryEscape(empty)+"&offset=1"); code != http.StatusBadRequest {
		t.Errorf("空文件 offset=1 期望 400 实得 %d", code)
	}
	if code, _ := doGet(t, h, "/fs/read?path="+url.QueryEscape(filepath.Join(root, "gone.bin"))); code != http.StatusNotFound {
		t.Errorf("读不存在文件期望 404 实得 %d", code)
	}
}

// TestFSHash 与 crypto/sha256 直算对比 + 字段存在性 + 目录/缺失分支。
func TestFSHash(t *testing.T) {
	root := t.TempDir()
	h := New(Deps{StartTime: time.Now()})

	p := filepath.Join(root, "sample.bin")
	data := append([]byte("HEAD"), make([]byte, 300000)...)
	for i := 4; i < len(data); i++ {
		data[i] = byte(i * 13)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	code, body := doGet(t, h, "/fs/hash?path="+url.QueryEscape(p))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	sum := sha256.Sum256(data)
	if d["sha256"] != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 与直算不符: %v", d["sha256"])
	}
	if sz, ok := d["size"].(float64); !ok || int64(sz) != int64(len(data)) {
		t.Errorf("size 期望 %d 实得 %v", len(data), d["size"])
	}
	auth, ok := d["authenticode"].(map[string]any)
	if !ok {
		t.Fatalf("authenticode 结构缺失: %v", body)
	}
	for _, k := range []string{"state", "subject", "issuer"} {
		if _, ok := auth[k]; !ok {
			t.Errorf("authenticode 缺字段 %s（契约 §5.2）", k)
		}
	}
	// state 必有真实取值（临时文件预期 unsigned，但映射规则不写死）
	if s, _ := auth["state"].(string); s == "" {
		t.Errorf("authenticode.state 为空: %v", auth)
	}

	// 目录 → 400；不存在 → 404
	if code, _ := doGet(t, h, "/fs/hash?path="+url.QueryEscape(root)); code != http.StatusBadRequest {
		t.Errorf("哈希目录期望 400 实得 %d", code)
	}
	if code, _ := doGet(t, h, "/fs/hash?path="+url.QueryEscape(filepath.Join(root, "gone.exe"))); code != http.StatusNotFound {
		t.Errorf("哈希不存在文件期望 404 实得 %d", code)
	}
}

// bigFS 桩：造不出真 2GB 文件，用 FSys 注入验证上限分支。
type bigFS struct{}

func (bigFS) List(dir string) ([]Entry, error)               { return nil, ErrNotDir }
func (bigFS) Stat(path string) (Entry, error)                { return Entry{Name: "big.bin", Size: 3 << 30}, nil }
func (bigFS) Open(path string) (io.ReadCloser, int64, error) { return nil, 0, ErrNotExist }

func TestFSHashSizeCap(t *testing.T) {
	h := New(Deps{StartTime: time.Now(), FS: bigFS{}})
	code, body := doGet(t, h, "/fs/hash?path="+url.QueryEscape(`C:\big.bin`))
	if code != http.StatusBadRequest {
		t.Fatalf(">2GB 期望 400 实得 %d body=%v", code, body)
	}
}
