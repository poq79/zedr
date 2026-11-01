// Package enrich 为进程补充"贵"信号：文件哈希、数字签名、路径分类。
//
// 这些操作是 IO / 密码学开销的主要来源，因此全部带缓存：
// 同一路径 + 同一 (size, mtime) 只算一次，按 LRU 上限淘汰。
package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hostguard/internal/agent/winapi"
)

// Meta 是进程镜像的富化结果。
type Meta struct {
	Path        string
	Hash        string
	FileSize    int64
	ModTime     time.Time
	Signed      bool
	SignatureOK bool
	Signer      string
	SigState    string
	InSystem    bool
	DirWritable bool
	Depth       int
	Exists      bool
}

// Enricher 带缓存的富化器。
type Enricher struct {
	maxHashMB int64

	calcMu sync.Mutex // 串行化"哈希+签名"计算，避免同路径并发重复计算
	mu     sync.Mutex
	files  map[string]*fileCacheEntry // path -> 文件属性+哈希+签名
	order  []string
	maxEnt int
}

type fileCacheEntry struct {
	size    int64
	modTime time.Time
	hash    string
	sig     winapi.SignatureResult
	sigDone bool
}

// New 创建富化器；maxHashMB<=0 表示不限制。
func New(maxHashMB int64) *Enricher {
	return &Enricher{
		maxHashMB: maxHashMB,
		files:     make(map[string]*fileCacheEntry, 4096),
		maxEnt:    20000,
	}
}

// Stats 返回缓存规模（用于本地 UI 展示）。
func (e *Enricher) Stats() (int, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.files), cap(e.order)
}

// Describe 返回路径的完整元数据（哈希 + 签名 + 路径分类）。
//
// 锁策略：先用短锁查缓存，只有真正需要计算（哈希/验签）时才去抢串行锁。
//
// 早期版本是"进函数就抢 calcMu"，结果是缓存命中的调用也要排队——
// 而扫描循环每个新进程都会调它，一串排队下来整轮扫描被拉长，
// 表现为持续性的 CPU 占用偏高。
func (e *Enricher) Describe(path string) Meta {
	m := Meta{Path: path}
	if path == "" {
		return m
	}

	// 快速路径：stat + 缓存命中（无串行锁）
	st, err := os.Stat(path)
	if err != nil {
		m.InSystem, m.DirWritable, m.Depth = classifyPath(path)
		return m
	}
	m.Exists = true
	m.FileSize = st.Size()
	m.ModTime = st.ModTime().UTC()
	m.InSystem, m.DirWritable, m.Depth = classifyPath(path)

	if ent := e.lookup(path, st.Size(), st.ModTime()); ent != nil && ent.sigDone {
		e.fill(&m, ent)
		return m
	}

	// 慢速路径：确实需要计算
	e.calcMu.Lock()
	defer e.calcMu.Unlock()

	// 双重检查：可能已被并发的另一次调用算好
	if ent := e.lookup(path, st.Size(), st.ModTime()); ent != nil && ent.sigDone {
		e.fill(&m, ent)
		return m
	}

	entry := e.lookup(path, st.Size(), st.ModTime())
	if entry == nil {
		entry = &fileCacheEntry{size: st.Size(), modTime: st.ModTime()}
		// 哈希（大文件跳过，避免 IO 抖动）
		if e.maxHashMB <= 0 || st.Size() <= e.maxHashMB*1024*1024 {
			if h, err := hashFile(path); err == nil {
				entry.hash = h
			}
		}
		e.store(path, entry)
	}

	m.Hash = entry.hash

	// 签名单独 lazy 计算：只有需要时才算（例如哈希未命中白名单）
	if !entry.sigDone {
		entry.sig = winapi.VerifySignature(path)
		entry.sigDone = true
	}
	e.fill(&m, entry)
	return m
}

// fill 把缓存条目写进返回值。
func (e *Enricher) fill(m *Meta, entry *fileCacheEntry) {
	m.Hash = entry.hash
	m.Signed = entry.sig.Signed
	m.SignatureOK = entry.sig.Valid
	m.Signer = entry.sig.Signer
	m.SigState = entry.sig.State
}

// DescribeFast 只返回路径分类（不碰磁盘），用于低成本事件裁剪。
func DescribeFast(path string) (inSystem, dirWritable bool, depth int) {
	return classifyPath(path)
}

func (e *Enricher) lookup(path string, size int64, mt time.Time) *fileCacheEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.files[path]
	if !ok {
		return nil
	}
	if ent.size != size || !ent.modTime.Equal(mt) {
		return nil // 文件已变化，重新计算
	}
	return ent
}

func (e *Enricher) store(path string, ent *fileCacheEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.files[path]; !exists {
		e.order = append(e.order, path)
	}
	e.files[path] = ent

	// 简单的 FIFO 淘汰（新进程路径分布很散，FIFO 足够）
	if len(e.order) > e.maxEnt {
		drop := len(e.order) - e.maxEnt
		for i := 0; i < drop; i++ {
			delete(e.files, e.order[i])
		}
		e.order = append([]string(nil), e.order[drop:]...)
	}
}

// Invalidate 在文件被替换后主动失效缓存。
func (e *Enricher) Invalidate(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.files, path)
}

// hashFile 计算文件 SHA256。
//
// 用 1MB 缓冲而不是 io.Copy 默认的 32KB：
// 哈希是纯 IO + CPU 的顺序操作，缓冲区太小会让系统调用次数成为瓶颈。
// 实测对 10MB 级可执行文件能明显减少耗时（进程镜像大多在这个量级）。
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, 1<<20)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------- 路径分类

var (
	systemDirsOnce sync.Once
	systemDirs     []string
	writableDirs   []string
)

func initDirs() {
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	systemDirs = []string{
		strings.ToLower(filepath.Join(win, "System32")),
		strings.ToLower(filepath.Join(win, "SysWOW64")),
		strings.ToLower(filepath.Join(win, "WinSxS")),
		strings.ToLower(filepath.Join(win, "servicing")),
		strings.ToLower(filepath.Join(win, "SystemApps")),
	}

	candidates := []string{
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		os.Getenv("APPDATA"),
		os.Getenv("LOCALAPPDATA"),
		os.Getenv("USERPROFILE"),
		os.Getenv("PUBLIC"),
		os.Getenv("ProgramData"),
		filepath.Join(win, "Temp"),
		filepath.Join(win, "Tasks"),
		filepath.Join(win, "Fonts"),
		`C:\PerfLogs`,
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		lc := strings.ToLower(c)
		// USERPROFILE 整体算可写，但其中 Desktop/Documents/Downloads 才是高发区
		writableDirs = append(writableDirs, lc)
	}
	// 回收站按卷展开
	for _, d := range []string{`C:\$Recycle.Bin`, `D:\$Recycle.Bin`} {
		writableDirs = append(writableDirs, strings.ToLower(d))
	}
}

// classifyPath 判断路径是否位于系统目录 / 用户可写目录，以及目录深度。
func classifyPath(path string) (inSystem, dirWritable bool, depth int) {
	systemDirsOnce.Do(initDirs)
	lower := strings.ToLower(filepath.Clean(path))

	for _, d := range systemDirs {
		if strings.HasPrefix(lower, d+`\`) {
			inSystem = true
			break
		}
	}
	// 注意：Windows\System32 已覆盖；Windows 根目录下的其它工具不算系统目录
	if !inSystem && (strings.HasPrefix(lower, `c:\windows\`) || strings.HasPrefix(lower, `c:\windows\system32\`)) {
		// Windows 目录本体（如 C:\Windows\explorer.exe）也按系统目录对待
		if !strings.Contains(lower, `\temp\`) {
			inSystem = true
		}
	}

	for _, d := range writableDirs {
		if d != "" && strings.HasPrefix(lower, d+`\`) {
			dirWritable = true
			break
		}
	}

	depth = strings.Count(lower, `\`)
	return inSystem, dirWritable, depth
}
