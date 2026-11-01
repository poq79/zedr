package liveapi

// analyze_test.go：/analyze 端点。
// 策略分三层：
//  1. 纯 Go 造文件：三哈希/字符串分类/非 PE/损坏 PE/超限 400；
//  2. 桩 FSys：验证"Stat 就超限"分支不必造 65MB 真文件；
//  3. 真机冒烟（notepad.exe）：PE 解析/imphash/版本资源链路在本机成立，
//     文件不存在时 skip 兜底。

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// stubFS 桩：只服务 /analyze 的 Stat/Open 组合。
type stubFS struct {
	stat    Entry  // Name 为空 = 一律不存在
	content []byte // Open 返回的内容
	openErr error  // Open 报错（模拟权限等）
}

func (f stubFS) List(dir string) ([]Entry, error) { return nil, ErrNotExist }

func (f stubFS) Stat(path string) (Entry, error) {
	if f.stat.Name == "" {
		return Entry{}, ErrNotExist
	}
	return f.stat, nil
}

func (f stubFS) Open(path string) (io.ReadCloser, int64, error) {
	if f.openErr != nil {
		return nil, 0, f.openErr
	}
	// bytes.Reader 自带 ReadAt：analyze 的 PE 随机访问依赖它
	return nopReadCloser{bytes.NewReader(f.content)}, int64(len(f.content)), nil
}

type nopReadCloser struct{ *bytes.Reader }

func (nopReadCloser) Close() error { return nil }

// utf16le 把 s 编成 UTF-16LE 字节（模拟 Windows 宽字符常量的存储形态）。
func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestAnalyzeHashesAndStrings(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sample.bin")

	var content []byte
	// 一行一个候选（空格是可打印字符，会并进同一串——分类按整串前缀判）
	content = append(content, []byte("padding text here\n")...)
	content = append(content, []byte("http://evil.example.com/payload\n")...)
	content = append(content, []byte("10.0.0.5\n")...)
	content = append(content, []byte("HKLM\\Software\\Microsoft\\Run\n")...)
	content = append(content, []byte("C:\\Users\\tester\\implant.dll\n")...)
	content = append(content, []byte("Global\\svc_mutex_x\n")...)
	// UTF-16LE 形态的 URL（用 NUL 与 ASCII 区隔；前面补 1 字节让
	// UTF-16 数据落在奇偏移，覆盖未对齐窗口的真实场景）
	content = append(content, []byte{0x01}...)
	content = append(content, utf16le("https://wide.example.net/drop")...)
	content = append(content, []byte{0, 0}...)
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}

	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/analyze?path="+url.QueryEscape(file))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)

	// 三哈希与 crypto 直算对比
	m5, s1, s256 := md5.Sum(content), sha1.Sum(content), sha256.Sum256(content)
	if d["md5"] != hex.EncodeToString(m5[:]) {
		t.Errorf("md5 不符: %v", d["md5"])
	}
	if d["sha1"] != hex.EncodeToString(s1[:]) {
		t.Errorf("sha1 不符: %v", d["sha1"])
	}
	if d["sha256"] != hex.EncodeToString(s256[:]) {
		t.Errorf("sha256 不符: %v", d["sha256"])
	}
	if sz, _ := d["size"].(float64); int64(sz) != int64(len(content)) {
		t.Errorf("size 期望 %d 实得 %v", len(content), d["size"])
	}
	// 非 PE：pe 字段缺席
	if _, ok := d["pe"]; ok {
		t.Errorf("纯文本不应有 pe 块: %v", d["pe"])
	}

	str, _ := json.Marshal(d["strings"])
	var sr struct {
		URLs          []string `json:"urls"`
		IPs           []string `json:"ips"`
		RegistryPaths []string `json:"registry_paths"`
		FilePaths     []string `json:"file_paths"`
		Mutex         []string `json:"mutex"`
	}
	if err := json.Unmarshal(str, &sr); err != nil {
		t.Fatalf("strings 结构不符: %v raw=%s", err, str)
	}
	assertContains(t, "urls", sr.URLs, "http://evil.example.com/payload")
	assertContains(t, "urls(UTF-16)", sr.URLs, "https://wide.example.net/drop")
	assertContains(t, "ips", sr.IPs, "10.0.0.5")
	assertContains(t, "registry", sr.RegistryPaths, "HKLM\\Software\\Microsoft\\Run")
	assertContains(t, "filepath", sr.FilePaths, "C:\\Users\\tester\\implant.dll")
	assertContains(t, "mutex", sr.Mutex, "Global\\svc_mutex_x")
}

func assertContains(t *testing.T, what string, list []string, want string) {
	t.Helper()
	for _, v := range list {
		if v == want {
			return
		}
	}
	t.Errorf("%s 缺少 %q: %v", what, want, list)
}

func TestAnalyzeBrokenPE(t *testing.T) {
	// MZ 头 + 垃圾：不是合法 PE → pe 块缺席（解析失败不伪造结论），
	// 哈希/strings 照常
	dir := t.TempDir()
	file := filepath.Join(dir, "fake.exe")
	if err := os.WriteFile(file, append([]byte("MZ"), make([]byte, 300)...), 0o644); err != nil {
		t.Fatal(err)
	}
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/analyze?path="+url.QueryEscape(file))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)
	if _, ok := d["pe"]; ok {
		t.Errorf("损坏 PE 不应有 pe 块: %v", d["pe"])
	}
	if d["sha256"] == "" {
		t.Errorf("哈希应照常输出")
	}
}

func TestAnalyzeTooLargeStub(t *testing.T) {
	// 桩 FSys 把 Stat 尺寸报成 65MB：不造真文件即可验证上限分支
	big := stubFS{stat: Entry{Name: "big.bin", Size: analyzeMaxBytes + 1}}
	h := New(Deps{StartTime: time.Now(), FS: big})
	code, body := doGet(t, h, "/analyze?path=C:\\x\\big.bin")
	if code != http.StatusBadRequest {
		t.Fatalf("超 64MB 期望 400 实得 %d body=%v", code, body)
	}

	missing := stubFS{} // Name 空 = 不存在
	h = New(Deps{StartTime: time.Now(), FS: missing})
	if code, _ := doGet(t, h, "/analyze?path=C:\\x\\gone.bin"); code != http.StatusNotFound {
		t.Fatalf("不存在期望 404 实得 %d", code)
	}
}

func TestAnalyzeDirectoryRejected(t *testing.T) {
	h := New(Deps{StartTime: time.Now()})
	if code, _ := doGet(t, h, "/analyze?path="+url.QueryEscape(t.TempDir())); code != http.StatusBadRequest {
		t.Fatalf("目录期望 400")
	}
}

// TestAnalyzeRealBinarySmoke 真机冒烟：PE 解析/imphash/版本资源链路。
func TestAnalyzeRealBinarySmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "notepad.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("notepad.exe 不可用: %v", err)
	}
	h := New(Deps{StartTime: time.Now()})
	code, body := doGet(t, h, "/analyze?path="+url.QueryEscape(path))
	if code != http.StatusOK {
		t.Fatalf("期望 200 实得 %d body=%v", code, body)
	}
	d := dataOf(t, body)

	if d["sha256"] == "" || d["md5"] == "" || d["sha1"] == "" {
		t.Fatal("三哈希缺失")
	}
	peRaw, err := json.Marshal(d["pe"])
	if err != nil || d["pe"] == nil {
		t.Fatalf("pe 块缺失: %v", err)
	}
	var pe struct {
		Machine           string  `json:"machine"`
		IsDLL             bool    `json:"is_dll"`
		MaxSectionEntropy float64 `json:"max_section_entropy"`
		ImpHash           string  `json:"imphash"`
		Imports           *struct {
			Total      int `json:"total"`
			Notable    []string
			Categories struct {
				Network int `json:"network"`
				Exec    int `json:"exec"`
			} `json:"categories"`
		} `json:"imports"`
	}
	if err := json.Unmarshal(peRaw, &pe); err != nil {
		t.Fatalf("pe 结构不符: %v raw=%s", err, peRaw)
	}
	if pe.Machine != "x86_64" && pe.Machine != "i386" {
		t.Errorf("machine 异常: %q", pe.Machine)
	}
	if pe.IsDLL {
		t.Errorf("notepad.exe 不应是 DLL")
	}
	if pe.MaxSectionEntropy <= 0 || pe.MaxSectionEntropy > 8 {
		t.Errorf("最大节熵超出 (0,8]: %v", pe.MaxSectionEntropy)
	}
	secs, ok := d["pe"].(map[string]any)["sections"].([]any)
	if !ok || len(secs) == 0 {
		t.Fatalf("sections 为空")
	}
	secCount := len(secs)
	// notepad 有导入表 → imphash 应为 32 位 hex；类别计数按本机事实断言
	//（记事本不引网络 DLL，network=0 是真实结论——不要断言它 >0）
	if pe.Imports == nil || pe.Imports.Total <= 0 {
		t.Fatalf("notepad 应有导入表: %+v", pe.Imports)
	}
	if pe.Imports.Total < 100 {
		t.Errorf("notepad 导入项应上百: %d", pe.Imports.Total)
	}
	if len(pe.ImpHash) != 32 {
		t.Errorf("imphash 应为 32 hex: %q", pe.ImpHash)
	}
	// 版本资源：MUI 重定向文件——资源声明的 OriginalFilename 是
	// NOTEPAD.EXE.MUI，与实际名 notepad.exe 不等 → mismatch:true 是
	// 如实结论（MUI 是 mismatch 的已知误报源，前端按"提示"渲染）
	vr, ok := d["version_resource"].(map[string]any)
	if !ok {
		t.Fatalf("version_resource 缺失: %v", d["version_resource"])
	}
	if vr["company"] != "Microsoft Corporation" {
		t.Errorf("company 不符: %v", vr["company"])
	}
	if vr["original_filename"] != "NOTEPAD.EXE.MUI" || vr["mismatch"] != true {
		t.Errorf("MUI 文件的 mismatch 语义不符: %v", vr)
	}
	t.Logf("sections=%d imphash=%s exec=%d network=%d",
		secCount, pe.ImpHash, pe.Imports.Categories.Exec, pe.Imports.Categories.Network)
}
