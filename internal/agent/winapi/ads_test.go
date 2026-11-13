//go:build windows
// +build windows

package winapi

// ads_test.go：流枚举与 Zone.Identifier 解析。
// ADS 依赖 NTFS：t.TempDir 通常在 %TEMP%（系统盘 NTFS），写入失败时
// skip 而非 fail（老机器可能有 FAT/ReFS 卷）。

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeADS 尝试给文件写一条命名流，返回是否成功（不支持 ADS 的卷 → false）。
func writeADS(t *testing.T, file, name, content string) bool {
	t.Helper()
	if err := os.WriteFile(file+":"+name, []byte(content), 0o644); err != nil {
		t.Logf("写入 ADS 失败（可能非 NTFS 卷）: %v", err)
		return false
	}
	return true
}

func TestEnumerateStreamsAndZone(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	dir := t.TempDir()
	marked := filepath.Join(dir, "downloaded.exe")
	if err := os.WriteFile(marked, []byte("MZfake-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.exe")
	if err := os.WriteFile(clean, []byte("MZfake-clean"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !writeADS(t, marked, "zone.identifier",
		"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://mail.example.com/a\r\nHostUrl=https://cdn.example.net/p.exe\r\nDownloadTime=11/02/2026 10:00\r\n") {
		t.Skip("本卷不支持 ADS")
	}

	// 命名流应被枚举出来（zone.identifier），主流 ::$DATA 不出现
	streams, err := EnumerateStreams(marked)
	if err != nil {
		t.Fatalf("EnumerateStreams 失败: %v", err)
	}
	found := false
	for _, s := range streams {
		if s.Name == "::$DATA" {
			t.Errorf("主流 ::$DATA 不应出现在结果中: %+v", streams)
		}
		if s.Name == "zone.identifier" {
			found = true
			if s.Size <= 0 {
				t.Errorf("流大小应 >0: %+v", s)
			}
		}
	}
	if !found {
		t.Fatalf("未枚举到 zone.identifier: %+v", streams)
	}

	// 无 ADS 文件：空流列表 + 无错误
	if streams, err := EnumerateStreams(clean); err != nil || len(streams) != 0 {
		t.Fatalf("无 ADS 文件期望 (空, nil) 实得 (%+v, %v)", streams, err)
	}

	// Zone.Identifier 解析
	zi, err := ReadZoneIdentifier(marked)
	if err != nil || zi == nil {
		t.Fatalf("ReadZoneIdentifier 期望解析结果: zi=%v err=%v", zi, err)
	}
	if zi.ZoneID != 3 {
		t.Errorf("ZoneId 期望 3 实得 %d", zi.ZoneID)
	}
	if zi.ReferrerURL != "https://mail.example.com/a" || zi.HostURL != "https://cdn.example.net/p.exe" {
		t.Errorf("Referrer/Host 解析不符: %+v", zi)
	}
	if zi.DownloadTime == "" {
		t.Errorf("DownloadTime 应保留原值: %+v", zi)
	}

	// 无 ADS → nil, nil
	if zi, err := ReadZoneIdentifier(clean); zi != nil || err != nil {
		t.Fatalf("无 ADS 期望 (nil, nil) 实得 (%v, %v)", zi, err)
	}

	// 不存在的文件：流枚举分类为 os.ErrNotExist
	if _, err := EnumerateStreams(filepath.Join(dir, "nope.exe")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("不存在路径期望 os.ErrNotExist 包装，实得 %v", err)
	}
}

func TestReadZoneIdentifierInvalid(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "broken.exe")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !writeADS(t, file, "zone.identifier", "[ZoneTransfer]\r\nZoneId=not-a-number\r\n") {
		t.Skip("本卷不支持 ADS")
	}
	// ZoneId 坏 → 整条 MotW 不可信，返回 nil（宁缺毋滥口径）
	zi, err := ReadZoneIdentifier(file)
	if zi != nil || err != nil {
		t.Fatalf("坏 ZoneId 期望 (nil, nil) 实得 (%v, %v)", zi, err)
	}
}
