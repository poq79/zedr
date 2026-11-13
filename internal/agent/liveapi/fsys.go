//go:build windows
// +build windows

package liveapi

// fsys.go：FSys 抽象与默认 OSFS 实现。
//
// 抽象的目的不是支持多种存储，而是：① 单测可注入桩实现，验证"2GB 上限"
// 这类造不出真文件的分支；② 把"只读"固化在类型里——接口面上根本不存在
// 写/删/移动，调查面的铁律不依赖实现自觉。

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"zedr/internal/agent/winapi"
)

// Entry 是目录条目（契约 §5.2）：只含 name，全路径由前端用 path 拼接。
type Entry struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	IsDir     bool   `json:"is_dir"`
	Hidden    bool   `json:"hidden"`
	System    bool   `json:"system"`
	Readonly  bool   `json:"readonly"`
	Reparse   bool   `json:"reparse"`
	MtimeUnix int64  `json:"mtime_unix"`
}

// FSys 是文件系统抽象：三个读操作，杜绝任何写语义。
type FSys interface {
	List(dir string) ([]Entry, error)
	Stat(path string) (Entry, error)
	Open(path string) (io.ReadCloser, int64, error)
}

// FSys 错误分类哨兵：handler 据此映射 HTTP 状态码（不存在 → 404、
// 目录/非目录 → 400、无权限 → 403），实现方无需理解 HTTP。
var (
	ErrNotExist   = errors.New("liveapi: 路径不存在")
	ErrIsDir      = errors.New("liveapi: 目标是目录")
	ErrNotDir     = errors.New("liveapi: 目标不是目录")
	ErrPermission = errors.New("liveapi: 访问被拒绝")
)

// OSFS 是 FSys 的默认实现，直读本机文件系统。
type OSFS struct{}

// List 列举目录。注意先 Stat 再 ReadDir：os.ReadDir 对"目标是文件"返回的
// 是 readdirent 失败的含糊错误，直接按 Stat 分类更可靠。
func (OSFS) List(dir string) ([]Entry, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, wrapFSErr(err)
	}
	if !info.IsDir() {
		return nil, ErrNotDir
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, wrapFSErr(err)
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		e := Entry{Name: de.Name(), IsDir: de.IsDir()}
		if fi, err := de.Info(); err == nil {
			e.Size = fi.Size()
			e.MtimeUnix = fi.ModTime().Unix()
		}
		// 属性逐条查询：目录可能被并发改动，个别条目会消失，
		// GetFileAttrs 失败返回零值，不让单条目失败放大成整目录失败
		a := winapi.GetFileAttrs(filepath.Join(dir, de.Name()))
		e.Hidden, e.System, e.Readonly, e.Reparse = a.Hidden, a.System, a.Readonly, a.Reparse
		out = append(out, e)
	}
	return out, nil
}

func (OSFS) Stat(path string) (Entry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Entry{}, wrapFSErr(err)
	}
	e := Entry{
		Name:      info.Name(),
		Size:      info.Size(),
		IsDir:     info.IsDir(),
		MtimeUnix: info.ModTime().Unix(),
	}
	a := winapi.GetFileAttrs(path)
	e.Hidden, e.System, e.Readonly, e.Reparse = a.Hidden, a.System, a.Readonly, a.Reparse
	return e, nil
}

// Open 打开文件供流式读取，返回 reader 与打开时刻的大小快照。
// os.Open 本身就是只读语义（无写标志），满足调查面铁律。
func (OSFS) Open(path string) (io.ReadCloser, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, wrapFSErr(err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, wrapFSErr(err)
	}
	if info.IsDir() {
		// Windows 上 os.Open 打开目录会成功，必须在句柄上显式拒绝
		_ = f.Close()
		return nil, 0, ErrIsDir
	}
	return f, info.Size(), nil
}

// wrapFSErr 把 os 错误归类成 FSys 哨兵错误（丢弃 os.ErrNotExist 的包装链
// 是有意的：调用方只需要类别，不需要底层 errno）。
func wrapFSErr(err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ErrNotExist
	case errors.Is(err, os.ErrPermission):
		return ErrPermission
	default:
		return err
	}
}
