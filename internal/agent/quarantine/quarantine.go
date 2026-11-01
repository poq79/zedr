// Package quarantine 实现文件隔离区：把可疑文件移出原位、改名入库、
// 记录清单，并可按清单恢复原状。
//
// 设计约束：
//   - 隔离区固定在探针数据目录下（dataDir/quarantine），与白名单/基线
//     同级——数据目录已自豁免、权限 0700，不需要额外提权；
//   - 拒绝隔离 HostGuard 自身安装/数据目录内的文件（自保护，
//     防止"删掉自己的检测数据"这类指令被滥用）；
//   - 跨卷移动用 copy+hash 校验+删除 原子化降级，任何一步失败都
//     不产生"两个副本都不完整"的状态；
//   - 清单与文件是同一事实源：清单丢失的隔离文件视为不可恢复，
//     恢复一律以清单为准，不凭记忆猜路径。
package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hostguard/internal/platform/idgen"
)

// Entry 是隔离清单里的一条记录。
type Entry struct {
	ID           string     `json:"id"`
	OriginalPath string     `json:"original_path"`
	StoredName   string     `json:"stored_name"`
	Size         int64      `json:"size"`
	SHA256       string     `json:"sha256"`
	Reason       string     `json:"reason"`
	By           string     `json:"by"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	RestoredAt   *time.Time `json:"restored_at,omitempty"`
}

// manifest 是清单文件结构（版本化，防止未来字段语义漂移时误读）。
type manifest struct {
	Schema  int     `json:"schema"`
	Entries []Entry `json:"entries"`
}

// Store 是隔离区。
type Store struct {
	dir     string
	manifestPath string
	// protected 前缀（小写、带尾分隔符规范化）内的文件拒绝隔离
	protected []string

	mu      sync.Mutex
	entries []Entry
}

// ErrLocked 等常见失败统一为错误值，供上层翻译成指令回执文案。
var (
	ErrNotFound      = errors.New("隔离记录不存在")
	ErrAlreadyGone   = errors.New("文件不存在或已被移动")
	ErrProtected     = errors.New("拒绝隔离 HostGuard 自身目录内的文件")
	ErrOriginalExists = errors.New("原路径已存在同名文件，拒绝覆盖")
	ErrAlreadyRestored = errors.New("该记录已恢复过")
)

// New 打开（或创建）数据目录下的隔离区。
// dataDir 与 installDir 内的文件受自保护。
func New(dataDir, installDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建隔离区目录失败: %w", err)
	}
	s := &Store{
		dir:          dir,
		manifestPath: filepath.Join(dir, "manifest.json"),
		protected:    protectedPrefixes(dataDir, installDir),
	}
	s.load()
	return s, nil
}

// List 返回未恢复的隔离记录。
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.RestoredAt == nil {
			out = append(out, e)
		}
	}
	return out
}

// Quarantine 把文件移入隔离区，返回记录。
func (s *Store) Quarantine(path, reason, by string) (*Entry, error) {
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("路径非法: %w", err)
	}
	if s.isProtected(abs) {
		return nil, ErrProtected
	}
	st, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrAlreadyGone
		}
		return nil, err
	}
	if st.IsDir() {
		return nil, errors.New("只支持隔离单个文件，不支持目录")
	}

	// 先算哈希：既做跨卷搬运校验，也写入清单供事后比对
	sum, err := fileSHA256(abs)
	if err != nil {
		return nil, fmt.Errorf("计算文件哈希失败: %w", err)
	}

	id := idgen.Hex(10)
	storedName := "qtn-" + id + ".bin"
	storedPath := filepath.Join(s.dir, storedName)

	// 同卷优先 rename（瞬时完成）；跨卷/失败降级为 copy+verify+delete
	if err := os.Rename(abs, storedPath); err != nil {
		if err2 := copyThenRemove(abs, storedPath, sum); err2 != nil {
			_ = os.Remove(storedPath) // 搬运失败不留半个副本
			return nil, err2
		}
	}

	e := &Entry{
		ID:            id,
		OriginalPath:  abs,
		StoredName:    storedName,
		Size:          st.Size(),
		SHA256:        sum,
		Reason:        reason,
		By:            by,
		QuarantinedAt: time.Now(),
	}
	s.mu.Lock()
	s.entries = append(s.entries, *e)
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		// 清单写不进去意味着"存了但说不清"，宁可回滚搬运
		_ = restoreFile(filepath.Join(s.dir, storedName), abs, sum)
		return nil, fmt.Errorf("写隔离清单失败（已回滚）: %w", err)
	}
	return e, nil
}

// Restore 按清单把文件放回原位。
func (s *Store) Restore(id, by string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i := range s.entries {
		if s.entries[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, ErrNotFound
	}
	e := &s.entries[idx]
	if e.RestoredAt != nil {
		return nil, ErrAlreadyRestored
	}

	if _, err := os.Stat(e.OriginalPath); err == nil {
		return nil, ErrOriginalExists
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	storedPath := filepath.Join(s.dir, e.StoredName)
	if err := restoreFile(storedPath, e.OriginalPath, e.SHA256); err != nil {
		return nil, err
	}
	now := time.Now()
	e.RestoredAt = &now
	e.By = e.By + "|" + by
	if err := s.saveLocked(); err != nil {
		// 文件已还原但清单没更新：重启后会当成"还在隔离"，可手动再恢复时发现
		return e, fmt.Errorf("更新隔离清单失败: %w", err)
	}
	return e, nil
}

// ---------------------------------------------------------------- 内部

func (s *Store) load() {
	raw, err := os.ReadFile(s.manifestPath)
	if err != nil {
		return
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Schema != 1 {
		return // 清单损坏不阻塞启动；隔离文件留在原处等待人工处理
	}
	s.entries = m.Entries
}

func (s *Store) saveLocked() error {
	m := manifest{Schema: 1, Entries: s.entries}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := s.manifestPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.manifestPath)
}

func (s *Store) isProtected(path string) bool {
	lp := normalizePrefix(path)
	for _, p := range s.protected {
		if strings.HasPrefix(lp, p) {
			return true
		}
	}
	return false
}

// protectedPrefixes 计算自保护前缀（含探针自身 exe 所在目录）。
func protectedPrefixes(dataDir, installDir string) []string {
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, normalizePrefix(abs))
		}
	}
	add(dataDir)
	add(installDir)
	return out
}

func normalizePrefix(p string) string {
	p = strings.ToLower(filepath.Clean(p))
	if !strings.HasSuffix(p, string(filepath.Separator)) {
		p += string(filepath.Separator)
	}
	return p
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyThenRemove 跨卷搬运：复制→哈希校验→删原件。任何一步失败都不删原件。
func copyThenRemove(src, dst, wantSHA string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建隔离副本失败: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		out.Close()
		return fmt.Errorf("复制失败: %w", err)
	}
	if err := out.Close(); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != wantSHA {
		return errors.New("复制后哈希不一致，中止搬运")
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("删除原文件失败（副本已留在隔离区）: %w", err)
	}
	return nil
}

// restoreFile 把隔离文件放回原位（同卷 rename，跨卷 copy+verify+remove）。
func restoreFile(storedPath, originalPath, wantSHA string) error {
	if err := os.Rename(storedPath, originalPath); err != nil {
		// 跨卷：copy → 校验 → 删隔离副本
		in, err := os.Open(storedPath)
		if err != nil {
			return fmt.Errorf("隔离文件读取失败: %w", err)
		}
		defer in.Close()
		out, err := os.OpenFile(originalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return fmt.Errorf("还原目标不可写: %w", err)
		}
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
			out.Close()
			return fmt.Errorf("还原复制失败: %w", err)
		}
		if err := out.Close(); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != wantSHA {
			_ = os.Remove(originalPath)
			return errors.New("还原后哈希不一致，已删除残缺副本")
		}
		if err := os.Remove(storedPath); err != nil {
			return fmt.Errorf("清理隔离副本失败: %w", err)
		}
	}
	return nil
}
