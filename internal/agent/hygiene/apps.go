//go:build windows
// +build windows

package hygiene

import (
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// InstalledApp 类型定义在 hygiene_types.go（双平台共享，Linux 由
// hygiene_linux.go 生产同形状数据）。

// uninstallEntry 是解析结果：app 之外还带去重键。
type uninstallEntry struct {
	key string
	app InstalledApp
}

// uninstallKeys 是三处 Win32 卸载注册表位置，覆盖 64/32 位与按用户安装。
var uninstallKeys = []struct {
	root registry.Key
	path string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.LOCAL_MACHINE, `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
}

// Apps 枚举已安装软件。单个键/单个条目读失败不影响整体——软件清单的
// 价值在于覆盖面，个别条目缺失不该让整个视图空白。
func Apps() []InstalledApp {
	apps := make([]InstalledApp, 0, 64)
	seen := make(map[string]bool)

	for _, uk := range uninstallKeys {
		root, err := registry.OpenKey(uk.root, uk.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := root.ReadSubKeyNames(-1)
		root.Close()
		if err != nil {
			continue
		}
		for _, sub := range names {
			e, ok := readUninstallEntry(uk.root, uk.path+`\`+sub)
			if !ok || seen[e.key] {
				continue
			}
			seen[e.key] = true
			apps = append(apps, e.app)
		}
	}

	apps = append(apps, storeApps()...)

	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Name != apps[j].Name {
			return apps[i].Name < apps[j].Name
		}
		return apps[i].Version < apps[j].Version
	})
	return apps
}

func readUninstallEntry(root registry.Key, path string) (uninstallEntry, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return uninstallEntry{}, false
	}
	defer k.Close()

	app := InstalledApp{Source: "win32"}
	app.Name, _, _ = k.GetStringValue("DisplayName")
	if strings.TrimSpace(app.Name) == "" {
		// 没有名字的条目对用户毫无意义（大量系统组件热修复键如此），跳过
		return uninstallEntry{}, false
	}
	app.Version, _, _ = k.GetStringValue("DisplayVersion")
	app.Publisher, _, _ = k.GetStringValue("Publisher")
	app.InstallDate, _, _ = k.GetStringValue("InstallDate")
	// InstallLocation 偶有自带引号的脏数据（百度网盘实测），剥掉再展示
	app.Location, _, _ = k.GetStringValue("InstallLocation")
	app.Location = strings.Trim(app.Location, `"`)
	if cmd, _, _ := k.GetStringValue("UninstallString"); cmd != "" {
		app.Location = firstNonEmpty(app.Location, exeFromCommand(cmd))
	}
	if sz, _, err := k.GetIntegerValue("EstimatedSize"); err == nil {
		app.SizeKB = uint64(sz)
	}
	app.Hidden = regDwordSet(k, "SystemComponent")
	app.NoRemove = regDwordSet(k, "NoRemove")

	return uninstallEntry{app.Name + "|" + app.Version + "|" + app.Publisher, app}, true
}

// regDwordSet 判断一个 DWORD 值是否存在且非零。
func regDwordSet(k registry.Key, name string) bool {
	v, _, err := k.GetIntegerValue(name)
	return err == nil && v != 0
}

// firstNonEmpty 定义在 hygiene_types.go（双平台共享）。

// storeApps 枚举 Microsoft Store（UWP/MSIX）应用。
//
// AppxAllUserStore\Applications 的子键名是 PackageFullName，格式
// Name_Version_Arch_ResourceID__PublisherHash；显示名优先读 DisplayName
// 值（部分系统版本有），没有就从键名前两段解析。机器级视图与当前用户
// 安装列表可能略有出入（含预配包），UI 会注明口径。
func storeApps() []InstalledApp {
	const path = `SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer root.Close()
	subs, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	apps := make([]InstalledApp, 0, len(subs))
	for _, full := range subs {
		app := InstalledApp{Source: "store"}
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+full, registry.QUERY_VALUE); err == nil {
			app.Name, _, _ = k.GetStringValue("DisplayName")
			app.Version, _, _ = k.GetStringValue("Version")
			app.Publisher, _, _ = k.GetStringValue("PublisherDisplayName")
			k.Close()
		}
		if app.Name == "" {
			// PackageFullName 前两段：名称_版本
			segs := strings.SplitN(full, "_", 4)
			if len(segs) >= 2 {
				app.Name = segs[0]
				app.Version = segs[1]
			} else {
				app.Name = full
			}
		}
		apps = append(apps, app)
	}
	return apps
}
