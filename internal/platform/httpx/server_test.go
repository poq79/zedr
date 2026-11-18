package httpx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSelfSigned 生成自签名证书对并落盘（仅测试用，IP SAN 127.0.0.1）。
func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zedr-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成证书: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码私钥: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("写证书: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("写私钥: %v", err)
	}
	return certPath, keyPath
}

// start 测试辅助：在随机端口启动并等待可连接。
func start(t *testing.T, c ServerConfig) *Server {
	t.Helper()
	s := NewServer(c)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	return s
}

func TestServerPlainHTTP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pong")) })
	s := start(t, ServerConfig{Addr: "127.0.0.1:0", Handler: mux})
	if s.IsTLS() {
		t.Fatal("未配置证书时不应报告 TLS")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + s.Addr() + "/ping")
	if err != nil {
		t.Fatalf("明文请求: %v", err)
	}
	resp.Body.Close()
}

func TestServerTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pong")) })
	s := start(t, ServerConfig{Addr: "127.0.0.1:0", Handler: mux, TLSCertFile: certPath, TLSKeyFile: keyPath})
	if !s.IsTLS() {
		t.Fatal("配置证书后应报告 TLS")
	}

	// 信任自签 CA：把测试证书自身加入根池
	der, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("读证书: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(der) {
		t.Fatal("证书无法加入根池")
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get("https://" + s.Addr() + "/ping")
	if err != nil {
		t.Fatalf("HTTPS 请求: %v", err)
	}
	resp.Body.Close()
}

func TestServerTLSBadCertPath(t *testing.T) {
	s := NewServer(ServerConfig{
		Addr:        "127.0.0.1:0",
		Handler:     http.NewServeMux(),
		TLSCertFile: filepath.Join(t.TempDir(), "missing.pem"),
		TLSKeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	})
	err := s.Listen()
	if err == nil {
		t.Fatal("证书路径不存在时 Listen 必须失败")
	}
	if want := "加载 TLS 证书"; !strings.Contains(err.Error(), want) {
		t.Fatalf("错误应包含 %q，got: %v", want, err)
	}
}
