//go:build linux

package tun

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

const tetherTCRecoveryPrefix = "sing-box-tether6/"

type tetherSavedFilter struct {
	id           uint32
	name         string
	originalName string
	original     *os.File
}

// Android's IPv6 tethering BPF forwards ACK/data by source prefix before
// netfilter, even when the SYN was intercepted by TPROXY. Pause only that
// program, leaving subsequent OEM classifiers and the IPv4 path intact.
type androidTetheringOffload struct {
	access         sync.Mutex
	active         bool
	options        *Options
	enableIPv6     bool
	logger         logger.Logger
	programPaths   []string
	lockPath       string
	leases         *os.File
	warning        string
	retryScheduled bool
	continueTag    string
	saved          map[tetherTCKey]tetherSavedFilter
}

func newAndroidTetheringOffload(options *Options, enableIPv6 bool, log logger.Logger) *androidTetheringOffload {
	return &androidTetheringOffload{
		active:     true,
		options:    options,
		enableIPv6: enableIPv6,
		logger:     log,
		lockPath:   "/data/local/sing-tun-tether6.lock",
		programPaths: []string{
			"/sys/fs/bpf/tethering/prog_offload_schedcls_tether_upstream6_ether",
			"/sys/fs/bpf/tethering/prog_offload_schedcls_tether_upstream6_rawip",
		},
		saved: make(map[tetherTCKey]tetherSavedFilter),
	}
}

func (m *androidTetheringOffload) includes(name string) bool {
	match := func(pattern string) bool {
		prefix, wildcard := strings.CutSuffix(pattern, "+")
		return name == pattern || wildcard && strings.HasPrefix(name, prefix)
	}
	return m.enableIPv6 && name != "lo" && name != m.options.Name &&
		!slices.ContainsFunc(m.options.BridgeInterface, match) &&
		(len(m.options.IncludeInterface) == 0 || slices.ContainsFunc(m.options.IncludeInterface, match)) &&
		!slices.ContainsFunc(m.options.ExcludeInterface, match)
}

func (m *androidTetheringOffload) update() error {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.active {
		return nil
	}
	return m.reconcile()
}

// The Binder caller closes a session only once. Retry transient failures here
// and retain the original FD and the lease until restoration or handoff succeeds.
func (m *androidTetheringOffload) close() error {
	m.access.Lock()
	defer m.access.Unlock()
	m.active = false
	err := m.releaseAll()
	if err != nil && !m.retryScheduled {
		// Give the Binder teardown path a chance to complete synchronously,
		// even when its root process exits immediately after Close.
		time.Sleep(25 * time.Millisecond)
		err = m.releaseAll()
	}
	if err != nil && !m.retryScheduled {
		m.retryScheduled = true
		go m.retryClose()
	}
	return err
}

func (m *androidTetheringOffload) retryClose() {
	for delay := 100 * time.Millisecond; ; delay = min(2*delay, 30*time.Second) {
		time.Sleep(delay)
		m.access.Lock()
		err := m.releaseAll()
		m.access.Unlock()
		if err == nil {
			return
		}
	}
}

func (m *androidTetheringOffload) releaseAll() error {
	var errs []error
	for key := range m.saved {
		if err := m.release(key); err != nil {
			errs = append(errs, err)
		}
	}
	if len(m.saved) == 0 && m.leases != nil {
		m.leases.Close()
		m.leases = nil
	}
	return errors.Join(errs...)
}

// Only cooperative sessions take this lock. Classic RTM_NEWTFILTER has no
// expected program ID; netd can still race the final identity check.
func (m *androidTetheringOffload) lock() error {
	if m.leases == nil {
		file, err := openTetherLeaseFile(m.lockPath)
		if err != nil {
			return err
		}
		m.leases = file
	}
	return tetherFileLock(m.leases, unix.LOCK_EX)
}

func (m *androidTetheringOffload) release(key tetherTCKey) error {
	if err := m.lock(); err != nil {
		return err
	}
	defer tetherFileLock(m.leases, unix.LOCK_UN)
	saved := m.saved[key]
	other, err := otherTetherUsers(m.leases, saved.id)
	if err != nil {
		return err
	}
	if !other {
		current, found, err := currentTetherTCFilter(key)
		if err != nil {
			return err
		}
		if found && current.id == saved.id && current.name == saved.name {
			err = current.replace(int(saved.original.Fd()), saved.originalName)
			if err != nil && !tetherTCGone(err) {
				return err
			}
		}
	}
	if err := setTetherLease(m.leases, saved.id, unix.F_UNLCK); err != nil {
		return err
	}
	saved.original.Close()
	delete(m.saved, key)
	return nil
}

func (m *androidTetheringOffload) reconcile() error {
	links, err := netlink.LinkList()
	if err != nil {
		m.reportProbe(err.Error())
		return nil
	}
	var errs []error
	seen := make(map[tetherTCKey]bool)
	var warnings []string
	for _, link := range links {
		attrs := link.Attrs()
		filters, err := listTetherTCFilters(attrs.Index)
		if err != nil {
			if !tetherTCGone(err) {
				warnings = append(warnings, fmt.Sprintf("list filters on %s: %v", attrs.Name, err))
				for key := range m.saved {
					if key.link == int32(attrs.Index) {
						seen[key] = true
					}
				}
			}
			continue
		}
		for _, f := range filters {
			key := f.key()
			manage := m.includes(attrs.Name)
			if saved, ok := m.saved[key]; ok {
				if manage && saved.id == f.id && saved.name == f.name {
					seen[key] = true
					continue
				}
				if err := m.release(key); err != nil {
					errs = append(errs, err)
					seen[key] = true
					continue
				}
			}
			seen[key] = true
			if !manage && !strings.HasPrefix(f.name, tetherTCRecoveryPrefix) {
				continue
			}
			probe, err := m.consider(f, manage)
			if probe != "" {
				warnings = append(warnings, attrs.Name+": "+probe)
			}
			if err != nil && !tetherTCGone(err) {
				errs = append(errs, E.Cause(err, "manage IPv6 tethering offload on ", attrs.Name))
			}
		}
	}
	for key := range m.saved {
		if !seen[key] {
			if err := m.release(key); err != nil {
				errs = append(errs, err)
			}
		}
	}
	slices.Sort(warnings)
	m.reportProbe(strings.Join(slices.Compact(warnings), "; "))
	return errors.Join(errs...)
}

func (m *androidTetheringOffload) reportProbe(warning string) {
	if warning != "" && warning != m.warning {
		m.logger.Warn("IPv6 tethering offload: ", warning)
	}
	m.warning = warning
}

func tetherTCGone(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESTALE)
}

// A probe error is diagnostic until a pinned program matches a live filter.
// A matching placeholder records which Android pin and display name to restore.
func (m *androidTetheringOffload) original(f tetherTCFilter) (file *os.File, pin, name, warning string) {
	recovery, paused := strings.CutPrefix(f.name, tetherTCRecoveryPrefix)
	name = f.name
	var wantPin, wantTag string
	if paused {
		parts := strings.SplitN(recovery, "/", 3)
		if len(parts) != 3 {
			return
		}
		wantPin, wantTag, name = parts[0], parts[1], parts[2]
	}
	for _, path := range m.programPaths {
		pin = filepath.Base(path)
		if paused && pin != wantPin {
			continue
		}
		fd, info, err := tetherBPFOpenProgram(path)
		if err != nil {
			if !errors.Is(err, unix.ENOENT) {
				warning = fmt.Sprintf("open %s: %v", path, err)
			}
			continue
		}
		tag := hex.EncodeToString(info.tag[:])
		if (!paused && f.id != info.id) || (paused && tag != wantTag) {
			unix.Close(fd)
			continue
		}
		// Check the named Android pin before loading a probe, which may
		// require raising the process memlock limit on older kernels.
		if paused {
			if m.continueTag == "" {
				probeFD, probeInfo, err := tetherBPFLoadContinue()
				if err != nil {
					unix.Close(fd)
					return nil, "", "", err.Error()
				}
				m.continueTag = hex.EncodeToString(probeInfo.tag[:])
				unix.Close(probeFD)
			}
			if f.tag != m.continueTag {
				unix.Close(fd)
				return nil, "", "", ""
			}
		}
		return os.NewFile(uintptr(fd), path), pin + "/" + tag, name, ""
	}
	if paused && warning == "" {
		warning = "original pinned tethering program unavailable for " + f.name
	}
	return nil, "", "", warning
}

func (m *androidTetheringOffload) consider(f tetherTCFilter, manage bool) (string, error) {
	original, pin, name, warning := m.original(f)
	if original == nil {
		return warning, nil
	}
	// Only verified targets need a coordination file.
	defer func() {
		if original != nil {
			original.Close()
		}
	}()
	if err := m.lock(); err != nil {
		return "", err
	}
	defer tetherFileLock(m.leases, unix.LOCK_UN)
	key := f.key()
	current, found, err := currentTetherTCFilter(key)
	if err != nil || !found {
		return "", err
	}
	if current.id != f.id || current.name != f.name {
		// A different session may have paused the original during discovery.
		original.Close()
		original, pin, name, warning = m.original(current)
		if original == nil {
			return warning, nil
		}
	}
	paused := strings.HasPrefix(current.name, tetherTCRecoveryPrefix)
	if !manage {
		if !paused {
			return "", nil
		}
		other, err := otherTetherUsers(m.leases, current.id)
		if err != nil || other {
			return "", err
		}
		return "", current.replace(int(original.Fd()), name)
	}
	id, marker := current.id, current.name
	var replacementFD int
	if !paused {
		fd, info, err := tetherBPFLoadContinue()
		if err != nil {
			if errors.Is(err, errTetherBPFLoadDenied) {
				return fmt.Sprintf("leaving original filter active; tethered IPv6 traffic may bypass auto-redirect: %v", err), nil
			}
			return "", err
		}
		defer unix.Close(fd)
		replacementFD, id = fd, info.id
		m.continueTag = hex.EncodeToString(info.tag[:])
		marker = tetherTCRecoveryPrefix + pin + "/" + name
	}
	if err := setTetherLease(m.leases, id, unix.F_RDLCK); err != nil {
		return "", err
	}
	if !paused {
		if err := current.replace(replacementFD, marker); err != nil {
			_ = setTetherLease(m.leases, id, unix.F_UNLCK)
			return "", err
		}
	}
	m.saved[key] = tetherSavedFilter{id: id, name: marker, originalName: name, original: original}
	original = nil
	return "", nil
}

func (r *autoRedirect) updateAndroidTetheringOffload() error {
	if r.androidTetheringOffload == nil {
		return nil
	}
	return r.androidTetheringOffload.update()
}

func (r *autoRedirect) cleanupAndroidTetheringOffload() error {
	if r.androidTetheringOffload == nil {
		return nil
	}
	return r.androidTetheringOffload.close()
}
