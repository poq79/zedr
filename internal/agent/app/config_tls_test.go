package agentapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestCAPEM 生成自签名 CA 证书 PEM（仅测试用）。
func writeTestCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "zedr-agent-test-ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("写 CA: %v", err)
	}
	return path
}

// loadWithEnv 在隔离环境变量下跑 LoadConfig（只留 TLS 相关三项）。
func loadWithEnv(t *testing.T, serverURL, requireTLS, caFile string) (*Config, error) {
	t.Helper()
	t.Setenv("HG_AGENT_SERVER_URL", serverURL)
	t.Setenv("HG_AGENT_REQUIRE_TLS", requireTLS)
	t.Setenv("HG_AGENT_TLS_CA_FILE", caFile)
	// 隔离其余可能干扰的开关：这组测试只关心 TLS 校验分支；
	// 数据目录指向临时目录，避免测试副作用落到真实数据目录
	t.Setenv("HG_AGENT_ENROLL_TOKEN", "test-token")
	t.Setenv("HG_AGENT_DATA_DIR", t.TempDir())
	return LoadConfig("test")
}

func TestRequireTLSAutoRejectsPlainRemote(t *testing.T) {
	_, err := loadWithEnv(t, "http://10.9.8.7:8080", "auto", "")
	if err == nil {
		t.Fatal("非回环明文在 auto 口径必须拒绝")
	}
	if want := "非回环地址禁止明文"; !containsStr(err.Error(), want) {
		t.Fatalf("错误应包含 %q，got: %v", want, err)
	}
}

func TestRequireTLSAutoAllowsLoopback(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		if _, err := loadWithEnv(t, url, "auto", ""); err != nil {
			t.Fatalf("回环 %s 应放行: %v", url, err)
		}
	}
}

func TestRequireTLSTrueRejectsPlainLoopback(t *testing.T) {
	_, err := loadWithEnv(t, "http://127.0.0.1:8080", "true", "")
	if err == nil || !containsStr(err.Error(), "要求 https") {
		t.Fatalf("true 口径应拒绝 http（含回环），got: %v", err)
	}
}

func TestRequireTLSFalseAllowsPlainRemote(t *testing.T) {
	cfg, err := loadWithEnv(t, "http://10.9.8.7:8080", "false", "")
	if err != nil {
		t.Fatalf("显式 false 是运维逃生门，应放行: %v", err)
	}
	if cfg.TLSCAPool != nil {
		t.Fatal("未配 CA 文件时池应为 nil")
	}
}

func TestCAFileValidLoadsPool(t *testing.T) {
	ca := writeTestCAPEM(t)
	cfg, err := loadWithEnv(t, "https://zedr.corp.local:8080", "auto", ca)
	if err != nil {
		t.Fatalf("https + 有效 CA 应通过: %v", err)
	}
	if cfg.TLSCAPool == nil {
		t.Fatal("CA 文件有效时 TLSCAPool 必须加载")
	}
}

func TestCAFileInvalidPEMRejected(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWithEnv(t, "https://zedr.corp.local:8080", "auto", bad); err == nil {
		t.Fatal("无效 PEM 必须拒绝启动")
	}
}

func TestCAFileOnPlainHTTPRejected(t *testing.T) {
	ca := writeTestCAPEM(t)
	_, err := loadWithEnv(t, "http://127.0.0.1:8080", "auto", ca)
	if err == nil || !containsStr(err.Error(), "只对 https") {
		t.Fatalf("CA 文件配在明文连接上应拒绝，got: %v", err)
	}
}

func TestRequireTLSInvalidValueRejected(t *testing.T) {
	if _, err := loadWithEnv(t, "https://zedr.corp.local:8080", "maybe", ""); err == nil {
		t.Fatal("非法取值必须拒绝")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.9.9.9", true},
		{"localhost", true},
		{"LOCALhost:443", true},
		{"[::1]:8080", true},
		{"10.0.0.5:8080", false},
		{"zedr.corp.local", false},
		{"[fe80::1]:8080", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackHost(c.host); got != c.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }
