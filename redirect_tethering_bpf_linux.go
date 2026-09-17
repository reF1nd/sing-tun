//go:build linux

package tun

import (
	"fmt"
	"runtime"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

type tetherBPFInstruction struct {
	code      uint8
	registers uint8
	offset    int16
	immediate int32
}

type tetherBPFProgramInfo struct {
	programType uint32
	id          uint32
	tag         [8]byte
}

func tetherBPFOpenProgram(path string) (int, tetherBPFProgramInfo, error) {
	var info tetherBPFProgramInfo
	name, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, info, err
	}
	var pin runtime.Pinner
	pin.Pin(name)
	defer pin.Unpin()
	attr := struct {
		path  uint64
		fd    uint32
		flags uint32
	}{path: uint64(uintptr(unsafe.Pointer(name)))}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, info, errno
	}
	info, err = tetherBPFGetProgramInfo(int(fd))
	if err != nil {
		unix.Close(int(fd))
		return -1, info, err
	}
	return int(fd), info, nil
}

func tetherBPFGetProgramInfo(fd int) (tetherBPFProgramInfo, error) {
	var info tetherBPFProgramInfo
	var pin runtime.Pinner
	pin.Pin(&info)
	defer pin.Unpin()
	attr := struct {
		fd     uint32
		length uint32
		info   uint64
	}{uint32(fd), uint32(unsafe.Sizeof(info)), uint64(uintptr(unsafe.Pointer(&info)))}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return info, errno
	}
	if info.programType != unix.BPF_PROG_TYPE_SCHED_CLS {
		return info, E.New("unexpected tethering BPF program type: ", info.programType)
	}
	return info, nil
}

func tetherBPFLoadProgram(name string, instructions []tetherBPFInstruction) (int, tetherBPFProgramInfo, error) {
	var info tetherBPFProgramInfo
	license := []byte("GPL\x00")
	log := make([]byte, 16*1024)
	var pin runtime.Pinner
	pin.Pin(&instructions[0])
	pin.Pin(&license[0])
	pin.Pin(&log[0])
	defer pin.Unpin()
	attr := struct {
		programType  uint32
		count        uint32
		instructions uint64
		license      uint64
		logLevel     uint32
		logSize      uint32
		log          uint64
		version      uint32
		flags        uint32
		name         [16]byte
	}{
		programType:  unix.BPF_PROG_TYPE_SCHED_CLS,
		count:        uint32(len(instructions)),
		instructions: uint64(uintptr(unsafe.Pointer(&instructions[0]))),
		license:      uint64(uintptr(unsafe.Pointer(&license[0]))),
		logLevel:     1,
		logSize:      uint32(len(log)),
		log:          uint64(uintptr(unsafe.Pointer(&log[0]))),
	}
	copy(attr.name[:15], name)
	fd, err := loadTetherBPFWithMemlock(func() (uintptr, unix.Errno) {
		log[0] = 0
		fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		return fd, errno
	}, raiseTetherMemlock)
	if err != nil {
		if detail := unix.ByteSliceToString(log); detail != "" {
			err = fmt.Errorf("%w (%s)", err, detail)
		}
		return -1, info, err
	}
	info, err = tetherBPFGetProgramInfo(int(fd))
	if err != nil {
		unix.Close(int(fd))
		return -1, info, err
	}
	return int(fd), info, nil
}

// Only an EPERM from PROG_LOAD can leave the original filter in place as a
// compatibility fallback. Pin access, program inspection and TC writes have
// their own error handling.
var errTetherBPFLoadDenied = fmt.Errorf("load tethering BPF program: %w", unix.EPERM)

func loadTetherBPFWithMemlock(load func() (uintptr, unix.Errno), raiseLimit func() error) (uintptr, error) {
	fd, errno := load()
	if errno == unix.EPERM {
		// Older Android kernels charge BPF allocations against RLIMIT_MEMLOCK.
		if err := raiseLimit(); err != nil {
			return 0, fmt.Errorf("%w (raise RLIMIT_MEMLOCK: %v)", errTetherBPFLoadDenied, err)
		}
		fd, errno = load()
		if errno == unix.EPERM {
			return 0, errTetherBPFLoadDenied
		}
	}
	if errno != 0 {
		return 0, E.Cause(errno, "load tethering BPF program")
	}
	return fd, nil
}

func raiseTetherMemlock() error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return err
	}
	if limit.Cur == unix.RLIM_INFINITY {
		return nil
	}
	unlimited := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unlimited)
	if err == nil {
		return nil
	}
	// A process without CAP_SYS_RESOURCE can still raise its soft limit to
	// the existing hard limit.
	if limit.Cur == limit.Max {
		return err
	}
	limit.Cur = limit.Max
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit)
}

func tetherBPFLoadContinue() (int, tetherBPFProgramInfo, error) {
	// TC_ACT_UNSPEC continues to the remaining classifiers, including OEM rules.
	return tetherBPFLoadProgram("sbox_tether6", []tetherBPFInstruction{
		{code: 0xb7, immediate: -1}, // r0 = TC_ACT_UNSPEC
		{code: 0x95},                // exit
	})
}
