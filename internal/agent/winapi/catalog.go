//go:build windows
// +build windows

package winapi

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows 系统二进制绝大多数不是"内嵌签名"，而是把签名放在 .cat 目录文件里。
// 只做 WinVerifyTrust(WTD_CHOICE_FILE) 会把 notepad.exe / cmd.exe 这类文件
// 误判为"无签名"，进而制造大量误报。因此必须补上 catalog 校验链路。
//
// 流程：计算文件哈希 → 在系统目录库中按哈希反查 catalog → WTD_CHOICE_CATALOG 验签。

var (
	procCryptCATAdminAcquireContext         = modWintrust.NewProc("CryptCATAdminAcquireContext")
	procCryptCATAdminCalcHashFromFileHandle = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle")
	procCryptCATAdminEnumCatalogFromHash    = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATAdminReleaseCatalogContext  = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext         = modWintrust.NewProc("CryptCATAdminReleaseContext")
	procCryptCATCatalogInfoFromContext      = modWintrust.NewProc("CryptCATCatalogInfoFromContext")
)

const wtdChoiceCatalog = 2

type catalogInfo struct {
	CbStruct       uint32
	WszCatalogFile [maxPath]uint16
}

type wintrustCatalogInfo struct {
	CbStruct             uint32
	DwCatalogVersion     uint32
	PcwszCatalogFilePath *uint16
	PcwszMemberTag       *uint16
	PcwszMemberFilePath  *uint16
	HMemberFile          windows.Handle
	PbCalculatedFileHash uintptr
	CbCalculatedFileHash uint32
	PcCatalogContext     uintptr
	HCatAdmin            uintptr
}

// VerifyCatalog 通过系统目录库校验文件的 catalog 签名。
// 返回 (结果, 是否命中并验签通过)。
func VerifyCatalog(path string) (SignatureResult, bool) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return SignatureResult{}, false
	}

	fh, err := windows.CreateFile(pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return SignatureResult{}, false
	}
	defer windows.CloseHandle(fh)

	var hCatAdmin uintptr
	ret, _, _ := procCryptCATAdminAcquireContext.Call(
		uintptr(unsafe.Pointer(&hCatAdmin)), 0, 0)
	if ret == 0 || hCatAdmin == 0 {
		return SignatureResult{}, false
	}
	defer func() { _, _, _ = procCryptCATAdminReleaseContext.Call(hCatAdmin, 0) }()

	var cbHash uint32
	_, _, _ = procCryptCATAdminCalcHashFromFileHandle.Call(
		uintptr(fh), uintptr(unsafe.Pointer(&cbHash)), 0, 0)
	if cbHash == 0 {
		cbHash = 20
	}
	hashBuf := make([]byte, cbHash)
	ret, _, _ = procCryptCATAdminCalcHashFromFileHandle.Call(
		uintptr(fh), uintptr(unsafe.Pointer(&cbHash)),
		uintptr(unsafe.Pointer(&hashBuf[0])), 0)
	if ret == 0 {
		return SignatureResult{}, false
	}

	// 同一文件几乎只对应一个 catalog，因此只查一次，避免复杂的枚举释放时序
	var prevCatInfo uintptr
	catCtx, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(
		hCatAdmin,
		uintptr(unsafe.Pointer(&hashBuf[0])),
		uintptr(cbHash), 0,
		uintptr(unsafe.Pointer(&prevCatInfo)))
	if catCtx == 0 {
		return SignatureResult{}, false
	}
	defer func() {
		_, _, _ = procCryptCATAdminReleaseCatalogContext.Call(hCatAdmin, catCtx, 0)
	}()

	var ci catalogInfo
	ci.CbStruct = uint32(unsafe.Sizeof(ci))
	ret, _, _ = procCryptCATCatalogInfoFromContext.Call(catCtx, uintptr(unsafe.Pointer(&ci)), 0)
	if ret == 0 {
		return SignatureResult{}, false
	}

	// 成员标签 = 文件哈希的十六进制大写串
	hexBytes := make([]byte, 0, len(hashBuf)*2)
	const upper = "0123456789ABCDEF"
	for _, b := range hashBuf {
		hexBytes = append(hexBytes, upper[b>>4], upper[b&0x0f])
	}
	tagPtr, err := windows.UTF16PtrFromString(string(hexBytes))
	if err != nil {
		return SignatureResult{}, false
	}

	catPath := windows.UTF16ToString(ci.WszCatalogFile[:])
	catPathPtr, err := windows.UTF16PtrFromString(catPath)
	if err != nil {
		return SignatureResult{}, false
	}

	catData := wintrustCatalogInfo{
		DwCatalogVersion:     1,
		PcwszCatalogFilePath: catPathPtr,
		PcwszMemberTag:       tagPtr,
		PcwszMemberFilePath:  pathPtr,
		HMemberFile:          fh,
		PbCalculatedFileHash: uintptr(unsafe.Pointer(&hashBuf[0])),
		CbCalculatedFileHash: cbHash,
		HCatAdmin:            hCatAdmin,
	}
	catData.CbStruct = uint32(unsafe.Sizeof(catData))

	data := wintrustData{
		DwUIChoice:          wtdUINone,
		FdwRevocationChecks: wtdRevokeNone,
		DwUnionChoice:       wtdChoiceCatalog,
		PFile:               uintptr(unsafe.Pointer(&catData)), // union 复用同一偏移
		DwStateAction:       wtdStateVerify,
	}
	data.CbStruct = uint32(unsafe.Sizeof(data))

	ret, _, _ = procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)))
	code := uint32(ret)

	data.DwStateAction = wtdStateClose
	_, _, _ = procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)))

	if code != 0 {
		return SignatureResult{}, false
	}

	signer := certSigner(catPath)
	if signer == "" {
		signer = "Windows Catalog"
	}
	return SignatureResult{
		Valid:   true,
		Signed:  true,
		Signer:  signer,
		State:   "valid_catalog",
		RawCode: 0,
	}, true
}
