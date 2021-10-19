package renderer

import (
	"github.com/pkg/errors"
	"log"
	"os"
	. "os/user"
)

type FilePerms interface {
	SetOwner(User) error
	SetGroup(Group) error
	GetPermissionBits() (os.FileMode, error)
	SetPermissionBits(os.FileMode) error
	Apply(path string) error
}

func lookupOwners(u string, g string) (*User, *Group, error) {
	var user *User
	var group *Group
	var err error
	if u != "" {
		if user, err = lookupUser(u); err != nil {
			return nil, nil, err
		}
	}
	if g != "" {
		if group, err = lookupGroup(g); err != nil {
			return nil, nil, err
		}
	}
	return user, group, nil
}

// Copy file permissions from srcPath to destPath with optional overrides. If
// neither srcPath nor override exist, use fallback.
func preserveFilePermissions(destPath string, srcPath string, override FilePermsInput, fallback FilePermsInput) error {
	_, err := os.Stat(srcPath)
	var perms FilePerms
	if err == nil {
		perms, err = getFilePermissions(srcPath)
	}
	if perms == nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARN] (runner) could not preserve file permissions from %q: %v", srcPath, err)
		}
		perms, err = NewFilePerms(&fallback)
		if err != nil {
			return errors.Wrap(err, "error using fallback file permissions")
		}
	}
	if err := override.ApplyTo(perms); err != nil {
		return errors.Wrap(err, "error using override file permissions")
	}
	if err := perms.Apply(destPath); err != nil {
		log.Printf("[WARN] (runner) could not set file permissions for %q: %v", destPath, err)
		return errors.Wrap(err, "error applying file permissions")
	}
	return nil
}

func (i FilePermsInput) ApplyTo(perms FilePerms) error {
	if i.User != "" {
		user, err := lookupUser(i.User)
		if err != nil {
			return err
		}
		if err := perms.SetOwner(*user); err != nil {
			return err
		}
	}
	if i.Group != "" {
		group, err := lookupGroup(i.Group)
		if err != nil {
			return err
		}
		if err := perms.SetGroup(*group); err != nil {
			return err
		}
	}
	if i.Mode != 0 {
		if err := perms.SetPermissionBits(i.Mode); err != nil {
			return err
		}
	}
	return nil
}

func Chown(name string, user string, group string) error {
	perms, err := NewFilePerms(&FilePermsInput{
		User:  user,
		Group: group,
	})
	if err != nil {
		return nil
	}
	return perms.Apply(name)
}

func Chmod(name string, mode os.FileMode) error {
	perms, err := NewFilePerms(&FilePermsInput{
		Mode: mode,
	})
	if err != nil {
		return nil
	}
	return perms.Apply(name)
}
