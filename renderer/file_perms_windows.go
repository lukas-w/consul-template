// +build windows

package renderer

import (
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"os"
	. "os/user"
	"time"
)

type WindowsFilePerms struct {
	desc *windows.SECURITY_DESCRIPTOR
}

func newUserTrustee(sid *windows.SID) *windows.TRUSTEE {
	return &windows.TRUSTEE{
		MultipleTrustee:          nil,
		MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
		TrusteeForm:              windows.TRUSTEE_IS_SID,
		TrusteeType:              windows.TRUSTEE_IS_USER,
		TrusteeValue:             windows.TrusteeValueFromSID(sid),
	}
}

func newGroupTrustee(sid *windows.SID) *windows.TRUSTEE {
	return &windows.TRUSTEE{
		MultipleTrustee:          nil,
		MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
		TrusteeForm:              windows.TRUSTEE_IS_SID,
		TrusteeType:              windows.TRUSTEE_IS_GROUP,
		TrusteeValue:             windows.TrusteeValueFromSID(sid),
	}
}

func NewFilePerms(input *FilePermsInput) (p WindowsFilePerms, err error) {
	p.desc, err = windows.NewSecurityDescriptor()
	if input != nil {
		err = input.ApplyTo(p)
	}
	return
}

func (p WindowsFilePerms) SetOwner(user User) error {
	sid, err := windows.StringToSid(user.Uid)
	if err != nil {
		return err
	}
	return p.desc.SetOwner(sid, false)
}

func (p WindowsFilePerms) SetGroup(group Group) error {
	sid, err := windows.StringToSid(group.Gid)
	if err != nil {
		return err
	}
	return p.desc.SetGroup(sid, false)
}
func (p WindowsFilePerms) GetPermissionBits() (mode os.FileMode, err error) {
	dacl, _, err := p.desc.DACL()
	if err != nil {
		return
	}
	ownerSid, _, err := p.desc.Owner()
	if err != nil {
		return 0, err
	}
	groupSid, _, err := p.desc.Group()
	if err != nil {
		return 0, err
	}
	_, _, worldSid, err := getWellKnownSids()
	if err != nil {
		return
	}

	ownerMask, err := getEffectiveRightsFromAcl(dacl, newUserTrustee(ownerSid))
	if err != nil {
		return
	}
	groupMask, err := getEffectiveRightsFromAcl(dacl, newGroupTrustee(groupSid))
	if err != nil {
		return
	}
	worldMask, err := getEffectiveRightsFromAcl(dacl, newGroupTrustee(worldSid))
	if err != nil {
		return
	}
	return accessMasksToFileMode(ownerMask, groupMask, worldMask), nil
}

func getWellKnownSids() (owner *windows.SID, group *windows.SID, world *windows.SID, err error) {
	owner, err = windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
	if err != nil {
		return
	}
	group, err = windows.CreateWellKnownSid(windows.WinCreatorGroupSid)
	if err != nil {
		return
	}
	world, err = windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return
	}
	return
}

func (p WindowsFilePerms) SetPermissionBits(fileMode os.FileMode) error {
	ownerSid, groupSid, worldSid, err := getWellKnownSids()
	if err != nil {
		return err
	}

	ownerMask, groupMask, worldMask := fileModeToAccessMasks(fileMode)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: ownerMask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *newUserTrustee(ownerSid),
		}, {
			AccessPermissions: groupMask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *newGroupTrustee(groupSid),
		}, {
			AccessPermissions: worldMask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           *newGroupTrustee(worldSid),
		},
	}, nil)
	if err == nil {
		p.desc.SetDACL(acl, true, false)
	}
	return err
}

func (p WindowsFilePerms) Apply(path string) error {
	ownerSID, ownerDefaulted, err := p.desc.Owner()
	if err != nil {
		return errors.Wrap(err, "error getting security descriptor owner")
	}
	groupSID, groupDefaulted, err := p.desc.Group()
	if err != nil {
		return errors.Wrap(err, "error getting security descriptor group")
	}
	dacl, daclDefaulted, err := p.desc.DACL()
	if err != nil {
		return errors.Wrap(err, "error getting security descriptor DACL")
	}

	var info windows.SECURITY_INFORMATION
	if ownerDefaulted || ownerSID == nil {
		ownerSID = nil
	} else {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	if groupDefaulted || ownerSID == nil {
		groupSID = nil
	} else {
		info |= windows.GROUP_SECURITY_INFORMATION
	}
	if daclDefaulted || dacl == nil {
		dacl = nil
	} else {
		info |= windows.DACL_SECURITY_INFORMATION
	}
	info |= windows.PROTECTED_DACL_SECURITY_INFORMATION

	if info == 0 {
		return nil
	}

	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, ownerSID, groupSID, dacl, nil)
}

func getFilePermissions(path string) (*WindowsFilePerms, error) {
	perms := WindowsFilePerms{}

	secInfo, err := windows.GetNamedSecurityInfo(path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, err
	}

	perms.desc = secInfo

	return &perms, nil
}

func lookupUser(s string) (user *User, err error) {
	if user, err = LookupId(s); err == nil {
		return
	}
	return Lookup(s)
}

func lookupGroup(s string) (group *Group, err error) {
	if group, err = LookupGroupId(s); err == nil {
		return
	}
	return LookupGroup(s)
}

type PermbitsSubject uint8

const (
	PermbitsOwner = 6
	PermbitsGroup = 3
	PermbitsWorld = 0
)

func fileModeToAccessMasks(mode os.FileMode) (ownerMask windows.ACCESS_MASK, groupMask windows.ACCESS_MASK, worldMask windows.ACCESS_MASK) {
	return fileModeToAccessMask(mode, PermbitsOwner), fileModeToAccessMask(mode, PermbitsGroup), fileModeToAccessMask(mode, PermbitsWorld)
}

func fileModeToAccessMask(mode os.FileMode, subject PermbitsSubject) (mask windows.ACCESS_MASK) {
	mode >>= subject
	if mode&0b100 != 0 {
		mask |= windows.FILE_GENERIC_READ
	}
	if mode&0b010 != 0 {
		mask |= windows.FILE_GENERIC_WRITE
	}
	if mode&0b001 != 0 {
		mask |= windows.FILE_GENERIC_EXECUTE
	}
	return
}

func accessMasksToFileMode(ownerMask windows.ACCESS_MASK, groupMask windows.ACCESS_MASK, worldMask windows.ACCESS_MASK) (mode os.FileMode) {
	return accessMaskToFileMode(ownerMask, PermbitsOwner) | accessMaskToFileMode(groupMask, PermbitsGroup) | accessMaskToFileMode(worldMask, PermbitsWorld)
}

func accessMaskToFileMode(mask windows.ACCESS_MASK, subject PermbitsSubject) (mode os.FileMode) {
	if mask&windows.FILE_GENERIC_READ != 0 {
		mode |= 0b100
	}
	if mask&windows.FILE_WRITE_DATA != 0 {
		mode |= 0b010
	}
	if mask&windows.FILE_EXECUTE != 0 {
		mode |= 0b001
	}
	return mode << subject
}

type WindowsFileInfo struct {
	info os.FileInfo
	mode os.FileMode
}

func Stat(name string) (info WindowsFileInfo, err error) {
	info.info, err = os.Stat(name)
	if err != nil {
		return
	}
	perms, err := getFilePermissions(name)
	if err != nil {
		return
	}
	info.mode, err = perms.GetPermissionBits()
	return
}

func (i WindowsFileInfo) Name() string {
	return i.info.Name()
}
func (i WindowsFileInfo) Size() int64 {
	return i.info.Size()
}
func (i WindowsFileInfo) Mode() os.FileMode {
	return i.mode
}
func (i WindowsFileInfo) ModTime() time.Time {
	return i.info.ModTime()
}
func (i WindowsFileInfo) IsDir() bool {
	return i.info.IsDir()
}
func (i WindowsFileInfo) Sys() interface{} {
	return i.info.Sys()
}
