//go:build windows
// +build windows

package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWintrust = windows.NewLazySystemDLL("wintrust.dll")
	modCrypt32  = windows.NewLazySystemDLL("crypt32.dll")

	procWinVerifyTrust              = modWintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject            = modCrypt32.NewProc("CryptQueryObject")
	procCertGetNameStringW          = modCrypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext  = modCrypt32.NewProc("CertFreeCertificateContext")
	procCertCloseStore              = modCrypt32.NewProc("CertCloseStore")
	procCryptMsgClose               = modCrypt32.NewProc("CryptMsgClose")
	procCertEnumCertificatesInStore = modCrypt32.NewProc("CertEnumCertificatesInStore")
)

// WINTRUST 常量
const (
	wtdUINone      = 2
	wtdRevokeNone  = 0
	wtdChoiceFile  = 1
	wtdStateVerify = 1
	wtdStateClose  = 2

	certQueryObjectFile       = 1
	certQueryContentPKCS7Any  = 0x00000500 // SIGNED_EMBED | SIGNED
	certQueryFormatBinary     = 0x00000002
	certNameSimpleDisplayType = 4

	trustENoSignature          = 0x800B0100
	trustESubjectFormUnknown   = 0x800B0003
	trustESubjectNotTrusted    = 0x800B0004
	trustEBadDigest            = 0x80096010
	trustEExplicitDistrust     = 0x800B0111
	certEUntrustedRoot         = 0x800B0109
	certEExpired               = 0x800B0101
	certEChainBasicConstraints = 0x800B0114
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2
var actionGenericVerifyV2 = guid{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

type wintrustFileInfo struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          uintptr
	PgKnownSubject uintptr
}

type wintrustData struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSIPClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               uintptr
	DwStateAction       uint32
	HWVTStateData       uintptr
	PwszURLReference    *uint16
	DwProvFlags         uint32
	DwUIContext         uint32
}

// SignatureResult 是 Authenticode 校验结果。Windows 专属形状（WinVerifyTrust
// 原始码等字段只有这里有）；跨平台调用方（enrich）用逐字段转换，避免
// winapi↔enrich import 成环。
type SignatureResult struct {
	Valid   bool   // 签名链是否可信通过
	Signed  bool   // 文件是否带有签名（即便不受信）
	Signer  string // 签名主体
	State   string // valid | unsigned | untrusted | expired | bad_digest | ...
	RawCode uint32 // WinVerifyTrust 原始返回码，便于排障
}

// VerifySignature 调用 WinVerifyTrust 校验文件 Authenticode 签名。
//
// 关键细节：必须用 WTD_STATEACTION_VERIFY 执行、再用 WTD_STATEACTION_CLOSE
// 释放状态，否则每次调用都会泄漏 WVT 状态句柄。同时不设置
// WTD_PROV_FLAG_CACHE_ONLY，否则部分文件的证书链无法从本地存储补齐，
// 会被误判成"无签名"。
func VerifySignature(path string) SignatureResult {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return SignatureResult{State: "error"}
	}

	fileInfo := wintrustFileInfo{PcwszFilePath: pathPtr}
	fileInfo.CbStruct = uint32(unsafe.Sizeof(fileInfo))

	data := wintrustData{
		DwUIChoice:          wtdUINone,
		FdwRevocationChecks: wtdRevokeNone,
		DwUnionChoice:       wtdChoiceFile,
		PFile:               uintptr(unsafe.Pointer(&fileInfo)),
		DwStateAction:       wtdStateVerify,
	}
	data.CbStruct = uint32(unsafe.Sizeof(data))

	ret, _, _ := procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)))
	code := uint32(ret)

	data.DwStateAction = wtdStateClose
	_, _, _ = procWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)))

	res := SignatureResult{RawCode: code}

	if code == 0 {
		res.Valid = true
		res.Signed = true
		res.State = "valid"
		res.Signer = certSigner(path)
		return res
	}

	switch code {
	case trustENoSignature, trustESubjectFormUnknown:
		res.State = "unsigned"
		// 内嵌签名缺失时，回退到系统 catalog 目录签名校验：
		// Windows 自带的 exe/dll 几乎都只在这一层有签名
		if cat, ok := VerifyCatalog(path); ok {
			return cat
		}
	case trustESubjectNotTrusted, trustEExplicitDistrust:
		res.Signed = true
		res.State = "distrusted"
	case trustEBadDigest:
		res.Signed = true
		res.State = "bad_digest" // 有签名但内容被篡改，高度可疑
	case certEExpired:
		res.Signed = true
		res.State = "expired"
	case certEUntrustedRoot, certEChainBasicConstraints:
		res.Signed = true
		res.State = "untrusted"
	default:
		res.State = fmt.Sprintf("error_0x%08x", code)
	}
	return res
}

// certSigner 从文件的 PKCS#7 签名中提取签名者显示名（尽力而为）。
func certSigner(path string) string {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}

	var (
		encodingType uint32
		contentType  uint32
		formatType   uint32
		certStore    uintptr
		msg          uintptr
	)

	ret, _, _ := procCryptQueryObject.Call(
		certQueryObjectFile,
		uintptr(unsafe.Pointer(pathPtr)),
		certQueryContentPKCS7Any,
		certQueryFormatBinary,
		0,
		uintptr(unsafe.Pointer(&encodingType)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&certStore)),
		uintptr(unsafe.Pointer(&msg)),
		0,
	)
	if ret == 0 || certStore == 0 {
		return ""
	}
	defer func() {
		if msg != 0 {
			_, _, _ = procCryptMsgClose.Call(msg)
		}
		_, _, _ = procCertCloseStore.Call(certStore, 0)
	}()

	cert, _, _ := procCertEnumCertificatesInStore.Call(certStore, 0)
	if cert == 0 {
		return ""
	}
	defer func() { _, _, _ = procCertFreeCertificateContext.Call(cert) }()

	n, _, _ := procCertGetNameStringW.Call(cert, certNameSimpleDisplayType, 0, 0, 0, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	ret2, _, _ := procCertGetNameStringW.Call(cert, certNameSimpleDisplayType, 0, 0,
		uintptr(unsafe.Pointer(&buf[0])), n)
	if ret2 == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
