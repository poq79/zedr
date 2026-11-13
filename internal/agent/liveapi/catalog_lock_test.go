//go:build windows
// +build windows

package liveapi

// catalog_lock_test.go：注册表与实现的启动期双向锁的测试面。
// New() 内部 panic 覆盖两个漂移方向（catalog 有 handler 无 / handler 有
// catalog 无）；这里再锁运行时行为——/_catalog 可取、条目数与注册表一致、
// 每个端点路由都真的注册了（405/404 语义区分）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"zedr/internal/livecatalog"
)

func TestNewBuildsAllCatalogRoutes(t *testing.T) {
	// New() 在任何漂移方向上都会 panic——能构造出来就是第一层锁
	h := New(Deps{Version: "test", Hostname: "lock"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_catalog")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("_catalog 状态码 %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			AgentVersion string `json:"agent_version"`
			Endpoints    []struct {
				Name string `json:"name"`
			} `json:"endpoints"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Data.AgentVersion != "test" {
		t.Fatalf("agent_version=%q", body.Data.AgentVersion)
	}
	if got := len(body.Data.Endpoints); got != len(livecatalog.All()) {
		t.Fatalf("_catalog 条目 %d != 注册表 %d", got, len(livecatalog.All()))
	}

	// 第二层锁：每个 catalog 端点的路由都真实存在。
	// 无参调用多数会 400/501（缺参数/未接线）——只断言"不是 404"，
	// 即路由已注册、落到 handler 了。
	client := &http.Client{}
	for _, ep := range livecatalog.All() {
		r, err := http.NewRequest(http.MethodGet, srv.URL+"/"+ep.Name, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s: %v", ep.Name, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("catalog 端点 %q 返回 404——路由未注册", ep.Name)
		}
	}
}
