package quarantine

import (
	"os"
	"path/filepath"
	"testing"
)

// TestQuarantineAndRestoreLifecycle 隔离→恢复全生命周期：
// 原文件消失、隔离区有副本、清单可查、恢复后字节一致、不可重复恢复。
func TestQuarantineAndRestoreLifecycle(t *testing.T) {
	dataDir := t.TempDir()
	workDir := t.TempDir()
	s, err := New(dataDir, "")
	if err != nil {
		t.Fatalf("初始化隔离区失败: %v", err)
	}

	original := filepath.Join(workDir, "evil.exe")
	if err := os.WriteFile(original, []byte("malicious-payload-bytes"), 0o644); err != nil {
		t.Fatalf("写测试文件失败: %v", err)
	}

	e, err := s.Quarantine(original, "演练告警 HG-001", "cmd-001")
	if err != nil {
		t.Fatalf("隔离失败: %v", err)
	}
	if _, err := os.Stat(original); !os.IsNotExist(err) {
		t.Fatal("原文件应已从原位置移除")
	}
	stored := filepath.Join(dataDir, "quarantine", e.StoredName)
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("隔离副本应存在: %v", err)
	}
	if e.SHA256 == "" || e.ID == "" {
		t.Fatalf("清单记录不完整: %+v", e)
	}
	if got := s.List(); len(got) != 1 {
		t.Fatalf("未恢复记录应为 1 条，实际 %d", len(got))
	}

	// 恢复：字节一致
	if _, err := s.Restore(e.ID, "cmd-002"); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	back, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("原文件应已恢复: %v", err)
	}
	if string(back) != "malicious-payload-bytes" {
		t.Fatalf("恢复后内容不一致: %q", back)
	}
	if _, err := os.Stat(stored); !os.IsNotExist(err) {
		t.Fatal("隔离副本应在恢复后清理")
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("恢复后未恢复记录应为 0，实际 %d", len(got))
	}

	// 重复恢复必须被拒
	if _, err := s.Restore(e.ID, "cmd-003"); err != ErrAlreadyRestored {
		t.Fatalf("重复恢复应返回 ErrAlreadyRestored，实际 %v", err)
	}
}

// TestQuarantineManifestPersists 重启（重新 New）后清单仍可恢复。
func TestQuarantineManifestPersists(t *testing.T) {
	dataDir := t.TempDir()
	workDir := t.TempDir()
	s, _ := New(dataDir, "")
	original := filepath.Join(workDir, "evil.dll")
	_ = os.WriteFile(original, []byte("payload-2"), 0o644)
	e, err := s.Quarantine(original, "演练", "cmd-1")
	if err != nil {
		t.Fatalf("隔离失败: %v", err)
	}

	// 模拟重启
	s2, err := New(dataDir, "")
	if err != nil {
		t.Fatalf("重开隔离区失败: %v", err)
	}
	if got := s2.List(); len(got) != 1 || got[0].ID != e.ID {
		t.Fatalf("重启后清单应保留记录，实际 %+v", s2.List())
	}
	if _, err := s2.Restore(e.ID, "cmd-2"); err != nil {
		t.Fatalf("重启后恢复失败: %v", err)
	}
}

// TestQuarantineGuards 自保护与防覆盖：
// 拒绝隔离数据目录内文件、原路径被占用时拒绝恢复、不存在文件报错。
func TestQuarantineGuards(t *testing.T) {
	dataDir := t.TempDir()
	workDir := t.TempDir()
	s, _ := New(dataDir, "")

	// 数据目录内的文件拒绝隔离（自保护）
	inner := filepath.Join(dataDir, "baseline.json")
	_ = os.WriteFile(inner, []byte("{}"), 0o600)
	if _, err := s.Quarantine(inner, "x", "by"); err != ErrProtected {
		t.Fatalf("应拒绝隔离数据目录内文件，实际 %v", err)
	}

	// 不存在的文件
	if _, err := s.Quarantine(filepath.Join(workDir, "ghost.exe"), "x", "by"); err != ErrAlreadyGone {
		t.Fatalf("不存在的文件应返回 ErrAlreadyGone，实际 %v", err)
	}

	// 目录拒绝
	if _, err := s.Quarantine(workDir, "x", "by"); err == nil {
		t.Fatal("目录应拒绝隔离")
	}

	// 原路径被同名文件占用时拒绝恢复（不覆盖）
	original := filepath.Join(workDir, "evil.exe")
	_ = os.WriteFile(original, []byte("payload-3"), 0o644)
	e, err := s.Quarantine(original, "x", "by")
	if err != nil {
		t.Fatalf("隔离失败: %v", err)
	}
	_ = os.WriteFile(original, []byte("someone-put-a-new-file"), 0o644)
	if _, err := s.Restore(e.ID, "by"); err != ErrOriginalExists {
		t.Fatalf("原路径被占用应拒绝恢复，实际 %v", err)
	}
}

// TestRestoreMissingRecord 不存在的隔离记录报 ErrNotFound。
func TestRestoreMissingRecord(t *testing.T) {
	s, _ := t.TempDir(), t.TempDir()
	st, _ := New(s, "")
	if _, err := st.Restore("no-such-id", "by"); err != ErrNotFound {
		t.Fatalf("应返回 ErrNotFound，实际 %v", err)
	}
}
