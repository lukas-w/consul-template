// +build windows

package renderer

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procGetEffectiveRightsFromAclW = modadvapi32.NewProc("GetEffectiveRightsFromAclW")
)

func getEffectiveRightsFromAcl(acl *windows.ACL, trustee *windows.TRUSTEE) (mask windows.ACCESS_MASK, err error) {
	r, _, _ := syscall.Syscall(procGetEffectiveRightsFromAclW.Addr(), 3, uintptr(unsafe.Pointer(acl)), uintptr(unsafe.Pointer(trustee)), uintptr(unsafe.Pointer(&mask)))
	if r != 0 {
		err = syscall.Errno(r)
	}
	return
}
