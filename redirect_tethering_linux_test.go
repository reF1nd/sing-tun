//go:build linux

package tun

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

func TestAndroidTetheringInterfaceScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		include []string
		exclude []string
		bridge  []string
		want    bool
	}{
		{name: "hotspot", want: true},
		{name: "lo"},
		{name: "tun0"},
		{name: "hotspot", include: []string{"lo"}},
		{name: "usb0", include: []string{"usb0"}, want: true},
		{name: "usb0", include: []string{"usb0"}, exclude: []string{"usb0"}},
		{name: "wlan2", include: []string{"wlan+"}, want: true},
		{name: "wlan2", exclude: []string{"wlan+"}},
		{name: "br0", bridge: []string{"br+"}},
	} {
		m := newAndroidTetheringOffload(&Options{Name: "tun0", IncludeInterface: tc.include, ExcludeInterface: tc.exclude, BridgeInterface: tc.bridge}, true, logger.NOP())
		if got := m.includes(tc.name); got != tc.want {
			t.Errorf("%+v: got %v", tc, got)
		}
		m.enableIPv6 = false
		if m.includes(tc.name) {
			t.Fatal("IPv6 disabled but interface selected")
		}
	}
}

func TestTetherBPFLoadMemlock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		loads    []unix.Errno
		raiseErr error
		wantErr  error
	}{
		{"success", []unix.Errno{0}, nil, nil},
		{"invalid-program", []unix.Errno{unix.EINVAL}, nil, unix.EINVAL},
		{"retry-success", []unix.Errno{unix.EPERM, 0}, nil, nil},
		{"raise-denied", []unix.Errno{unix.EPERM}, unix.EPERM, errTetherBPFLoadDenied},
		{"retry-denied", []unix.Errno{unix.EPERM, unix.EPERM}, nil, errTetherBPFLoadDenied},
		{"retry-other-error", []unix.Errno{unix.EPERM, unix.ENOMEM}, nil, unix.ENOMEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts, raises := 0, 0
			fd, err := loadTetherBPFWithMemlock(func() (uintptr, unix.Errno) {
				attempts++
				return 42, tc.loads[attempts-1]
			}, func() error {
				raises++
				return tc.raiseErr
			})
			if !errors.Is(err, tc.wantErr) || (err == nil && fd != 42) || attempts != len(tc.loads) {
				t.Fatalf("load returned fd=%d err=%v after %d attempts", fd, err, attempts)
			}
			if raises > 1 || (raises == 1) != (tc.loads[0] == unix.EPERM) {
				t.Fatalf("unexpected memlock adjustments: %d", raises)
			}
		})
	}
}

// SING_TUN_TEST_TETHERING=1 requires iproute2, bpffs, CAP_SYS_ADMIN,
// CAP_NET_ADMIN and permission to load BPF programs. Every case has its own
// network and mount namespaces. The Android binary also tests TC monitoring.
func TestAndroidTetheringOffloadKernel(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_TETHERING") != "1" {
		t.Skip("requires privileged Linux network namespaces and BPF")
	}
	if scenario := os.Getenv("SING_TUN_TEST_TETHERING_CASE"); scenario != "" {
		// The CLI case mounts over Android's system paths. Refuse to run a
		// manually selected child case in either of init's namespaces.
		if strings.HasPrefix(scenario, "android-cli") {
			for _, ns := range []string{"mnt", "net"} {
				current, err := os.Readlink("/proc/self/ns/" + ns)
				if err != nil {
					t.Fatal(err)
				}
				initNS, err := os.Readlink("/proc/1/ns/" + ns)
				if err != nil || current == initNS {
					t.Fatalf("CLI test requires an isolated %s namespace (init=%s, self=%s, err=%v)", ns, initNS, current, err)
				}
			}
		}
		testAndroidTetheringOffloadKernel(t, scenario)
		return
	}
	for _, scenario := range []string{"lifecycle", "chain", "late-and-replace", "orphan-recovery", "orphan-excluded", "scope", "foreign-replacement", "foreign-name", "rollback", "overlap", "overlap-excluded", "overlap-process", "close-retry", "close-once", "unidentified", "memlock", "data-path", "tc-events", "android-cli", "android-cli-load-denied"} {
		t.Run(scenario, func(t *testing.T) {
			if runtime.GOOS != "android" && (strings.HasPrefix(scenario, "android-cli") || scenario == "tc-events") {
				t.Skip("requires Android")
			}
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAndroidTetheringOffloadKernel$", "-test.v")
			cmd.Env = append(os.Environ(), "SING_TUN_TEST_TETHERING_CASE="+scenario)
			cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
		})
	}
}

type tetherKernelTest struct {
	t          *testing.T
	link       netlink.Link
	original   *netlink.BpfFilter
	originalFD int
	originalID uint32
	otherFD    int
	otherID    uint32
	pinPath    string
	manager    *androidTetheringOffload
}

func (s *tetherKernelTest) run(args ...string) {
	s.t.Helper()
	if output, err := exec.CommandContext(s.t.Context(), args[0], args[1:]...).CombinedOutput(); err != nil {
		s.t.Fatalf("%v: %v\n%s", args, err, output)
	}
}

func (s *tetherKernelTest) setup() {
	s.t.Helper()
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		s.t.Fatal(err)
	}
	s.run("ip", "link", "add", "hotspot", "type", "dummy")
	s.run("ip", "link", "set", "hotspot", "up")
	var err error
	s.link, err = netlink.LinkByName("hotspot")
	if err != nil {
		s.t.Fatal(err)
	}
	s.run("tc", "qdisc", "add", "dev", "hotspot", "clsact")
	// Simulate tethering: control packets enter the stack, ACK/data and UDP
	// are consumed before netfilter. ICMPv6 (including NDP) keeps working.
	s.originalFD, s.originalID = s.program("test_tether6", []tetherBPFInstruction{
		{code: 0x61, registers: 0x12, offset: 76}, // r2 = skb->data
		{code: 0x61, registers: 0x13, offset: 80}, // r3 = skb->data_end
		{code: 0xbf, registers: 0x24},
		{code: 0x07, registers: 4, immediate: 68},
		{code: 0x2d, registers: 0x34, offset: 7},  // short packet -> continue
		{code: 0x71, registers: 0x20, offset: 20}, // IPv6 next header
		{code: 0x15, immediate: 17, offset: 3},    // UDP -> drop
		{code: 0x55, immediate: 6, offset: 4},     // non-TCP -> continue
		{code: 0x71, registers: 0x20, offset: 67}, // TCP flags
		{code: 0x45, immediate: 7, offset: 2},     // SYN/FIN/RST -> continue
		{code: 0xb7, immediate: 2},
		{code: 0x95},
		{code: 0xb7, immediate: -1},
		{code: 0x95},
	})
	s.otherFD, s.otherID = s.program("test_other", []tetherBPFInstruction{{code: 0xb7, immediate: -1}, {code: 0x95}})
	dir := s.t.TempDir()
	if err = unix.Mount("bpf", dir, "bpf", 0, ""); err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = unix.Unmount(dir, 0) })
	s.pinPath = filepath.Join(dir, "prog_offload_schedcls_tether_upstream6_ether")
	name, err := unix.BytePtrFromString(s.pinPath)
	if err != nil {
		s.t.Fatal(err)
	}
	var pin runtime.Pinner
	pin.Pin(name)
	defer pin.Unpin()
	attr := struct {
		path  uint64
		fd    uint32
		flags uint32
	}{uint64(uintptr(unsafe.Pointer(name))), uint32(s.originalFD), 0}
	if _, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_PIN, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr)); errno != 0 {
		s.t.Fatal(errno)
	}
	s.original = s.filter(17, 0x42, unix.ETH_P_IPV6, s.originalFD, "android-tether-original")
	s.newManager()
}

func (s *tetherKernelTest) program(name string, instructions []tetherBPFInstruction) (int, uint32) {
	s.t.Helper()
	fd, info, err := tetherBPFLoadProgram(name, instructions)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { unix.Close(fd) })
	return fd, info.id
}

func (s *tetherKernelTest) filter(priority uint16, handle uint32, protocol uint16, fd int, name string) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: s.link.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Priority: priority, Handle: handle, Protocol: protocol},
		Fd:          fd, Name: name, DirectAction: true,
	}
}

func (s *tetherKernelTest) newManager() {
	m := newAndroidTetheringOffload(&Options{Name: "tun0"}, true, logger.NOP())
	m.programPaths = []string{s.pinPath}
	m.lockPath = filepath.Join(os.Getenv("SING_TUN_TEST_TETHER_LOCK_DIR"), "guard")
	s.manager = m
	s.t.Cleanup(func() {
		if err := m.close(); err != nil {
			s.t.Error(err)
		}
	})
}

func (s *tetherKernelTest) install(filter *netlink.BpfFilter) {
	s.t.Helper()
	if err := netlink.FilterReplace(filter); err != nil {
		s.t.Fatal(err)
	}
}

func (s *tetherKernelTest) update() {
	s.t.Helper()
	if err := s.manager.update(); err != nil {
		s.t.Fatal(err)
	}
}

func (s *tetherKernelTest) expectOriginal(paused bool) {
	s.t.Helper()
	filters, err := listTetherTCFilters(s.link.Attrs().Index)
	if err != nil {
		s.t.Fatal(err)
	}
	for _, f := range filters {
		if f.message.Handle != s.original.Handle || f.message.Info>>16 != uint32(s.original.Priority) {
			continue
		}
		if paused {
			if f.tag != s.manager.continueTag || !strings.HasPrefix(f.name, tetherTCRecoveryPrefix) {
				s.t.Fatalf("filter not paused: %+v", f)
			}
		} else if f.id != s.originalID || f.name != s.original.Name {
			s.t.Fatalf("original not restored: %+v", f)
		}
		return
	}
	s.t.Fatal("original filter location disappeared")
}

func testAndroidTetheringOffloadKernel(t *testing.T, scenario string) {
	s := &tetherKernelTest{t: t}
	t.Setenv("SING_TUN_TEST_TETHER_LOCK_DIR", t.TempDir())
	s.setup()
	switch scenario {
	case "android-cli", "android-cli-load-denied":
		s.androidCLI(scenario == "android-cli-load-denied")
	case "memlock":
		s.install(s.original)
		// Kernels that charge PROG_LOAD against the UID's locked memory
		// must raise the limit in this child to install the replacement.
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = 0
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Fatal(err)
		}
		s.update()
		s.expectOriginal(true)
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
	case "lifecycle":
		s.install(s.original)
		v4 := s.filter(18, 1, unix.ETH_P_IP, s.otherFD, "keep-ipv4")
		vendor := s.filter(49152, 1, unix.ETH_P_ALL, s.otherFD, "keep-oem")
		s.install(v4)
		s.install(vendor)
		s.update()
		s.expectOriginal(true)
		s.update()
		s.expectOriginal(true)
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
		filters, err := netlink.FilterList(s.link, netlink.HANDLE_MIN_INGRESS)
		if err != nil || len(filters) != 3 {
			t.Fatalf("unrelated filters changed: %v %v", filters, err)
		}
		for _, f := range filters {
			bpf := f.(*netlink.BpfFilter)
			if bpf.Priority != s.original.Priority && uint32(bpf.Id) != s.otherID {
				t.Fatalf("unrelated program replaced: %+v", bpf)
			}
		}
	case "overlap", "overlap-excluded":
		s.install(s.original)
		s.update()
		s.expectOriginal(true)
		first := s.manager
		s.newManager()
		if scenario == "overlap-excluded" {
			s.manager.enableIPv6 = false
		}
		s.update()
		s.expectOriginal(true)
		if err := first.update(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(true)
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(true)
		if err := first.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
	case "overlap-process":
		s.install(s.original)
		s.update()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTetherLeaseChild$")
		child.Env = append(os.Environ(), "SING_TUN_TEST_TETHER_PIN="+s.pinPath)
		ready, ack, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer ready.Close()
		defer ack.Close()
		child.ExtraFiles = []*os.File{ack}
		release, err := child.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer release.Close()
		child.Stderr = os.Stderr
		child.Stdout = os.Stdout
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		ack.Close()
		var signal [1]byte
		if _, err = io.ReadFull(ready, signal[:]); err != nil {
			t.Fatal(err)
		}
		if err = s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(true)
		release.Close()
		if err = child.Wait(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
	case "close-retry", "close-once":
		s.install(s.original)
		s.update()
		var old unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
			t.Fatal(err)
		}
		limit := old
		limit.Cur = 0
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
		err := s.manager.close()
		if e := unix.Setrlimit(unix.RLIMIT_NOFILE, &old); e != nil {
			t.Fatal(e)
		}
		if !errors.Is(err, unix.EMFILE) {
			t.Fatalf("expected transient close failure: %v", err)
		}
		if scenario == "close-retry" {
			if err = s.manager.close(); err != nil {
				t.Fatal(err)
			}
		} else {
			done := false
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
				s.manager.access.Lock()
				done = len(s.manager.saved) == 0 && s.manager.leases == nil
				s.manager.access.Unlock()
				if done {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !done {
				t.Fatal("one-shot Close did not retry restoration")
			}
		}
		s.expectOriginal(false)
	case "unidentified":
		s.install(s.filter(17, 0x42, unix.ETH_P_IPV6, s.otherFD, "foreign"))
		s.manager.programPaths = []string{"/dev/null"}
		s.update()
		if s.manager.warning == "" || s.manager.leases != nil {
			t.Fatal("unverified pin must be diagnostic only")
		}
		filters, err := listTetherTCFilters(s.link.Attrs().Index)
		if err != nil || len(filters) != 1 || filters[0].id != s.otherID {
			t.Fatal(filters, err)
		}
	case "chain":
		s.run("tc", "filter", "add", "dev", "hotspot", "ingress", "chain", "7", "protocol", "ipv6", "pref", "17", "handle", "0x42", "bpf", "da", "object-pinned", s.pinPath)
		filters, err := listTetherTCFilters(s.link.Attrs().Index)
		if err != nil || len(filters) != 1 || filters[0].chain != 7 {
			t.Fatalf("nondefault chain missing: %v %v", filters, err)
		}
		s.original.Name = filters[0].name
		s.update()
		s.expectOriginal(true)
		if err = s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
		filters, err = listTetherTCFilters(s.link.Attrs().Index)
		if err != nil || len(filters) != 1 || filters[0].chain != 7 {
			t.Fatalf("restore changed chain: %v %v", filters, err)
		}
	case "late-and-replace":
		s.update()
		s.install(s.original)
		s.update()
		s.expectOriginal(true)
		s.install(s.original) // netd reattaches the original filter
		s.update()
		s.expectOriginal(true)
		if err := netlink.FilterDel(s.original); err != nil {
			t.Fatal(err)
		}
		s.update()
		if len(s.manager.saved) != 0 {
			t.Fatal("deleted filter still owned")
		}
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		filters, _ := listTetherTCFilters(s.link.Attrs().Index)
		if len(filters) != 0 {
			t.Fatal("cleanup resurrected a detached filter")
		}
	case "orphan-recovery", "orphan-excluded":
		s.install(s.original)
		s.update()
		// Simulate process death: close descriptors without restoring TC.
		for _, saved := range s.manager.saved {
			saved.original.Close()
		}
		s.manager.leases.Close()
		clear(s.manager.saved)
		s.manager.leases = nil
		s.manager.active = false
		s.newManager()
		if scenario == "orphan-excluded" {
			s.manager.enableIPv6 = false
		}
		s.update()
		s.expectOriginal(scenario == "orphan-recovery")
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
	case "scope":
		s.install(s.original)
		s.manager.options.IncludeInterface = []string{"lo"}
		s.update()
		s.expectOriginal(false)
		s.manager.options.IncludeInterface = nil
		s.update()
		s.expectOriginal(true)
		s.manager.options.ExcludeInterface = []string{"hotspot"}
		s.update()
		s.expectOriginal(false)
	case "foreign-replacement", "foreign-name":
		s.install(s.original)
		s.update()
		foreign := *s.original
		foreign.Fd = s.otherFD // same name and location, different identity
		wantID := s.otherID
		if scenario == "foreign-name" {
			filters, err := listTetherTCFilters(s.link.Attrs().Index)
			if err != nil || len(filters) != 1 {
				t.Fatal(filters, err)
			}
			attr := struct{ id, next, flags uint32 }{id: filters[0].id}
			fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_GET_FD_BY_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
			if errno != 0 {
				t.Fatal(errno)
			}
			defer unix.Close(int(fd))
			foreign.Fd = int(fd)
			foreign.Name = "another-owner"
			wantID = filters[0].id
		}
		s.install(&foreign)
		s.update()
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		filters, _ := listTetherTCFilters(s.link.Attrs().Index)
		if len(filters) != 1 || filters[0].id != wantID || filters[0].name != foreign.Name {
			t.Fatal("overwrote another owner's filter")
		}
	case "rollback":
		s.install(s.original)
		// The existing name fits TC, but there is no room to record recovery
		// metadata. An error after the first replacement must be recoverable.
		tooLong := s.filter(18, 1, unix.ETH_P_IPV6, s.originalFD, strings.Repeat("x", 220))
		s.install(tooLong)
		if err := s.manager.update(); err == nil {
			t.Fatal("expected recovery metadata size error")
		}
		if err := s.manager.close(); err != nil {
			t.Fatal(err)
		}
		s.expectOriginal(false)
		filters, err := listTetherTCFilters(s.link.Attrs().Index)
		if err != nil || len(filters) != 2 || filters[1].id != s.originalID || filters[1].name != tooLong.Name {
			t.Fatalf("rollback changed original filters: %v %v", filters, err)
		}
	case "data-path":
		s.dataPath()
	case "tc-events":
		if runtime.GOOS != "android" {
			t.Skip("TC subscription is Android-specific; run the Android test binary")
		}
		monitor, err := NewNetworkUpdateMonitor(logger.NOP())
		if err != nil {
			t.Fatal(err)
		}
		if err = monitor.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = monitor.Close() })
		var updates atomic.Int32
		changed := make(chan error, 8)
		monitor.RegisterCallback(func() {
			updates.Add(1)
			changed <- s.manager.update()
		})
		s.install(s.original) // only a TC event; no route/link/address change
		select {
		case err = <-changed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("TC event did not schedule reconciliation")
		}
		s.expectOriginal(true)
		if updates.Load() == 0 {
			t.Fatal("no update callback")
		}
	default:
		t.Fatal(scenario)
	}
}

func denyTetherProgramLoad(t *testing.T) {
	t.Helper()
	// Deny just PROG_LOAD on this child thread, after pinning the real
	// fixture. Modern kernels need not enforce MEMLOCK for BPF.
	runtime.LockOSThread()
	argOffset := uint32(16) // seccomp_data.args[0], low word of the BPF command
	if binary.NativeEndian.Uint32([]byte{0, 0, 0, 1}) == 1 {
		argOffset += 4
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_BPF, Jf: 3},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: argOffset},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.BPF_PROG_LOAD, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		t.Fatal(errno)
	}
}

func (s *tetherKernelTest) androidCLI(denyLoad bool) {
	t := s.t
	s.run("ip", "link", "set", "lo", "up")
	// setup made this mount namespace private. Give the CLI its production
	// pin and lease paths without exposing the device's tethering state.
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("/sys/fs/bpf/tethering", 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(filepath.Dir(s.pinPath), "/sys/fs/bpf/tethering", "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", "/data/local", "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/data/local", 0)

	s.install(s.original)
	redirect, err := NewAutoRedirect(AutoRedirectOptions{
		Context: t.Context(), Logger: logger.NOP(), InterfaceFinder: control.NewDefaultInterfaceFinder(),
		TableName: "cli-test", TunOptions: &Options{
			Name: "tun0", Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if denyLoad {
		denyTetherProgramLoad(t)
	}
	if err := redirect.Start(); err != nil {
		t.Fatal(err)
	}
	r := redirect.(*autoRedirect)
	if r.androidTetheringOffload == nil {
		t.Fatal("standalone redirect did not initialize tethering offload")
	}
	s.manager = r.androidTetheringOffload
	if denyLoad && (len(s.manager.saved) != 0 || !strings.Contains(s.manager.warning, "hotspot: leaving original filter active")) {
		t.Fatalf("unexpected degraded state: saved=%d warning=%q", len(s.manager.saved), s.manager.warning)
	}
	s.expectOriginal(!denyLoad)
	s.install(s.original) // netd reattaches the original after startup
	if err := r.updateIPTablesNetwork(); err != nil {
		t.Fatal(err)
	}
	s.expectOriginal(!denyLoad)
	if err := redirect.Close(); err != nil {
		t.Fatal(err)
	}
	s.expectOriginal(false)
}

func (s *tetherKernelTest) dataPath() {
	s.run("ip", "link", "del", "hotspot")
	s.run("ip", "netns", "add", "client")
	s.t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", "client").Run() })
	s.run("ip", "link", "add", "hotspot", "type", "veth", "peer", "name", "peer0", "netns", "client")
	s.run("ip", "link", "set", "hotspot", "up")
	s.run("ip", "addr", "add", "2001:db8:1::1/64", "dev", "hotspot", "nodad")
	s.run("ip", "-n", "client", "link", "set", "peer0", "up")
	s.run("ip", "-n", "client", "addr", "add", "2001:db8:1::2/64", "dev", "peer0", "nodad")
	s.run("tc", "qdisc", "add", "dev", "hotspot", "clsact")
	var err error
	s.link, err = netlink.LinkByName("hotspot")
	if err != nil {
		s.t.Fatal(err)
	}
	s.original.LinkIndex = s.link.Attrs().Index
	s.install(s.original)
	listener, err := net.Listen("tcp6", "[2001:db8:1::1]:0")
	if err != nil {
		s.t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.Listener.Close()
	server.Listener = listener
	server.StartTLS()
	s.t.Cleanup(server.Close)
	udp, err := net.ListenPacket("udp6", "[2001:db8:1::1]:0")
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { udp.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			n, peer, readErr := udp.ReadFrom(buffer)
			if readErr != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], peer)
		}
	}()
	probe := func(target string, want bool) {
		s.t.Helper()
		cmd := exec.CommandContext(s.t.Context(), "ip", "netns", "exec", "client", os.Args[0], "-test.run=^TestTetheringProbe$")
		cmd.Env = append(os.Environ(), "SING_TUN_TETHERING_PROBE="+target)
		output, probeErr := cmd.CombinedOutput()
		if (probeErr == nil) != want {
			s.t.Fatalf("probe %s: expected success %v, error %v\n%s", target, want, probeErr, output)
		}
	}
	probe(server.URL, false)
	probe("udp://"+udp.LocalAddr().String(), false)
	s.update()
	s.expectOriginal(true)
	probe(server.URL, true)
	probe("udp://"+udp.LocalAddr().String(), true)
	// A later OEM filter must still get to reject a packet. TC_ACT_OK at
	// an earlier priority would incorrectly make this probe succeed.
	dropFD, _ := s.program("test_oem_drop", []tetherBPFInstruction{{code: 0xb7, immediate: 2}, {code: 0x95}})
	vendor := s.filter(49152, 1, unix.ETH_P_IPV6, dropFD, "oem-filter")
	s.install(vendor)
	probe(server.URL, false)
	if err = netlink.FilterDel(vendor); err != nil {
		s.t.Fatal(err)
	}
	probe(server.URL, true)
	if err = s.manager.close(); err != nil {
		s.t.Fatal(err)
	}
	s.expectOriginal(false)
	probe(server.URL, false)
}

// A separate process takes its own open-file-description lease, then waits
// until the parent (the original installer) has closed its session.
func TestTetherLeaseChild(t *testing.T) {
	path := os.Getenv("SING_TUN_TEST_TETHER_PIN")
	if path == "" {
		t.Skip("child of overlap-process")
	}
	m := newAndroidTetheringOffload(&Options{Name: "tun0"}, true, logger.NOP())
	m.lockPath = filepath.Join(os.Getenv("SING_TUN_TEST_TETHER_LOCK_DIR"), "guard")
	m.programPaths = []string{path}
	if err := m.update(); err != nil || len(m.saved) != 1 {
		t.Fatalf("join: %v, saved=%d", err, len(m.saved))
	}
	ready := os.NewFile(3, "ready")
	if _, err := ready.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	ready.Close()
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	if err := m.close(); err != nil {
		t.Fatal(err)
	}
}

func TestTetheringProbe(t *testing.T) {
	target := os.Getenv("SING_TUN_TETHERING_PROBE")
	if target == "" {
		t.Skip("helper for isolated tethering data-path tests")
	}
	if address, ok := strings.CutPrefix(target, "udp://"); ok {
		conn, err := net.DialTimeout("udp6", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		payload := "tethering IPv6 UDP test payload"
		if _, err = io.WriteString(conn, payload); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 100)
		n, err := conn.Read(buffer)
		if err != nil || string(buffer[:n]) != payload {
			t.Fatalf("UDP echo: %v %q", err, buffer[:n])
		}
		return
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "ok" {
		t.Fatal(errors.Join(err, fmt.Errorf("unexpected response %q", body)))
	}
}
