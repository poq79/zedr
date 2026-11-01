package recon

// web_test.go：IIS applicationHost.config 与 Tomcat server.xml 解析。
// 用 t.TempDir 造样例配置与 webroot，不依赖本机是否安装 IIS/Tomcat。

import (
	"html"
	"os"
	"path/filepath"
	"testing"
)

func TestParseIISConfig(t *testing.T) {
	root := t.TempDir()
	webroot := filepath.Join(root, "wwwroot")
	if err := os.MkdirAll(filepath.Join(webroot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webroot, "Default.aspx"), []byte("<%@ Page %>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webroot, "web.config"), []byte("<configuration/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "applicationHost.config")
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site" id="1" serverAutoStart="true">
        <bindings>
          <binding protocol="http" bindingInformation="*:8080:example.local" />
          <binding protocol="https" bindingInformation="127.0.0.1:8443:" />
        </bindings>
        <application path="/" applicationPool="DefaultAppPool">
          <virtualDirectory path="/" physicalPath="` + html.EscapeString(webroot) + `" />
        </application>
      </site>
    </sites>
  </system.applicationHost>
</configuration>`
	if err := os.WriteFile(configPath, []byte(xmlBody), 0o644); err != nil {
		t.Fatal(err)
	}

	sites, err := parseIISConfig(configPath)
	if err != nil {
		t.Fatalf("parseIISConfig: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("期望 1 个站点实得 %d: %+v", len(sites), sites)
	}
	site := sites[0]
	if site.Name != "Default Web Site" || site.ID != "1" {
		t.Fatalf("站点名/ID 不符: %+v", site)
	}
	if len(site.BindingDetails) != 2 {
		t.Fatalf("期望 2 条绑定实得 %d: %+v", len(site.BindingDetails), site.BindingDetails)
	}
	if b := site.BindingDetails[0]; b.Protocol != "http" || b.Address != "*" || b.Port != 8080 || b.Host != "example.local" {
		t.Fatalf("http 绑定解析不符: %+v", b)
	}
	if b := site.BindingDetails[1]; b.Protocol != "https" || b.Address != "127.0.0.1" || b.Port != 8443 {
		t.Fatalf("https 绑定解析不符: %+v", b)
	}
	if len(site.Bindings) != 2 || site.Bindings[0] != "http:*:8080:example.local" {
		t.Fatalf("绑定字符串（前端线协议）不符: %+v", site.Bindings)
	}
	if site.Webroot != webroot || site.PhysicalPath != webroot {
		t.Fatalf("webroot/physicalPath 期望 %q 实得 %q/%q", webroot, site.Webroot, site.PhysicalPath)
	}
	if !site.ASPXPresent || site.ASPXFiles != 1 || !site.HasWebConfig || !site.HasBin {
		t.Fatalf("webroot 抽查不符: %+v", site)
	}
}

func TestParseIISBindingIPv6(t *testing.T) {
	addr, port, host, ok := parseIISBinding("[::]:443:secure.example")
	if !ok || addr != "[::]" || port != 443 || host != "secure.example" {
		t.Fatalf("IPv6 绑定解析不符: addr=%q port=%d host=%q ok=%v", addr, port, host, ok)
	}
}

func TestParseTomcatConfig(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	serverXML := `<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005">
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" />
    <Connector port="8009" protocol="AJP/1.3" />
    <Engine name="Catalina">
      <Host name="localhost" appBase="webapps" />
    </Engine>
  </Service>
</Server>`
	path := filepath.Join(conf, "server.xml")
	if err := os.WriteFile(path, []byte(serverXML), 0o644); err != nil {
		t.Fatal(err)
	}
	webroot, ports := parseTomcatConfig(path)
	wantRoot := filepath.Join(root, "webapps")
	if webroot != wantRoot {
		t.Fatalf("webroot 期望 %q 实得 %q", wantRoot, webroot)
	}
	if len(ports) != 2 || ports[0] != 8080 || ports[1] != 8009 {
		t.Fatalf("Connector 端口解析不符: %v", ports)
	}
}
