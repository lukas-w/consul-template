// +build !windows

package renderer

import (
	"golang.org/x/sys/unix"
	"os"
	. "os/user"
	"strconv"
)

type PosixFilePerms struct {
	Mode os.FileMode
	Uid  *uint32
	Gid  *uint32
}

func NewFilePerms(input *FilePermsInput) (p PosixFilePerms, err error) {
	if input != nil {
		err = input.ApplyTo(p)
	}
	return
}

func (p PosixFilePerms) SetOwner(user User) error {
	return parseUint32(user.Uid, p.Uid)
}

func (p PosixFilePerms) SetGroup(group Group) error {
	return parseUint32(group.Gid, p.Gid)
}

func parseUint32(s string, i *uint32) error {
	uid, err := strconv.ParseUint(s, 10, 32)
	if err == nil {
		*i = uint32(uid)
	}
	return err
}

func (p PosixFilePerms) GetPermissionBits() (mode os.FileMode, err error) {
	return p.Mode, err
}

func (p PosixFilePerms) SetPermissionBits(mode os.FileMode) error {
	p.Mode = mode
	return nil
}

func (p PosixFilePerms) Apply(path string) error {
	if p.Mode != 0 {
		err := os.Chmod(path, p.Mode)
		if err != nil {
			return err
		}
	}
	uid := -1
	if p.Uid != nil {
		uid = int(*p.Uid)
	}
	gid := -1
	if p.Gid != nil {
		gid = int(*p.Gid)
	}
	err := os.Chown(path, uid, gid)
	return err
}

func getFilePermissions(path string) (*PosixFilePerms, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return nil, err
	}
	return &PosixFilePerms{
		Mode: os.FileMode(stat.Mode),
		Uid:  &stat.Uid,
		Gid:  &stat.Gid,
	}, nil
}

func lookupUser(s string) (*User, error) {
	if _, err := strconv.Atoi(s); err == nil {
		return LookupId(s)
	} else {
		return Lookup(s)
	}
}

func lookupGroup(s string) (*Group, error) {
	if _, err := strconv.Atoi(s); err == nil {
		return LookupGroupId(s)
	} else {
		return LookupGroup(s)
	}
}

func Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}
