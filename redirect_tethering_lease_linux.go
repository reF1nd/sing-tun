//go:build linux

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// All root services use the same inode. flock serializes their TC transitions;
// OFD read locks count live users of each installed placeholder across processes.
// Each attachment gets a fresh BPF program ID (unique kernel-wide while attached).
// The file stores no data. Unlinking it would split the lock domain.
func openTetherLeaseFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CLOEXEC|unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		file.Close()
		return nil, fmt.Errorf("unexpected owner or mode for tethering lock %s", path)
	}
	return file, nil
}

func tetherFileLock(file *os.File, operation int) error {
	for {
		err := unix.Flock(int(file.Fd()), operation)
		if err != unix.EINTR {
			return err
		}
	}
}

func setTetherLease(file *os.File, id uint32, kind int16) error {
	lock := unix.Flock_t{Type: kind, Start: int64(id), Len: 1}
	return unix.FcntlFlock(file.Fd(), unix.F_OFD_SETLK, &lock)
}

func otherTetherUsers(file *os.File, id uint32) (bool, error) {
	// GETLK ignores locks belonging to our own open file description.
	lock := unix.Flock_t{Type: unix.F_WRLCK, Start: int64(id), Len: 1}
	err := unix.FcntlFlock(file.Fd(), unix.F_OFD_GETLK, &lock)
	return lock.Type != unix.F_UNLCK, err
}
