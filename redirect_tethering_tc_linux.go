//go:build linux

package tun

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"syscall"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

type tetherTCKey struct {
	link   int32
	parent uint32
	info   uint32
	handle uint32
	chain  uint32
}

type tetherTCFilter struct {
	message nl.TcMsg
	chain   uint32
	options []syscall.NetlinkRouteAttr
	name    string
	id      uint32
	tag     string
	flags   uint32
}

func (f tetherTCFilter) key() tetherTCKey {
	return tetherTCKey{f.message.Ifindex, f.message.Parent, f.message.Info, f.message.Handle, f.chain}
}

func listTetherTCFilters(index int) ([]tetherTCFilter, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETTFILTER, unix.NLM_F_DUMP)
	req.AddData(&nl.TcMsg{Family: unix.AF_UNSPEC, Ifindex: int32(index), Parent: netlink.HANDLE_MIN_INGRESS})
	messages, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWTFILTER)
	// Links without ingress classifiers may not implement a filter dump.
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var filters []tetherTCFilter
	for _, message := range messages {
		filter, ok, parseErr := parseTetherTCFilter(message)
		if parseErr != nil {
			return nil, parseErr
		}
		if ok {
			filters = append(filters, filter)
		}
	}
	return filters, nil
}

func parseTetherTCFilter(message []byte) (tetherTCFilter, bool, error) {
	var f tetherTCFilter
	if len(message) < nl.SizeofTcMsg {
		return f, false, E.New("short TC filter message")
	}
	f.message = *nl.DeserializeTcMsg(message)
	if uint16(f.message.Info) != nl.Swap16(unix.ETH_P_IPV6) {
		return f, false, nil
	}
	attrs, err := nl.ParseRouteAttr(message[nl.SizeofTcMsg:])
	if err != nil {
		return f, false, err
	}
	var kind string
	var options []byte
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.TCA_KIND:
			kind = strings.TrimRight(string(attr.Value), "\x00")
		case nl.TCA_OPTIONS:
			options = attr.Value
		case unix.TCA_CHAIN:
			if len(attr.Value) != 4 {
				return f, false, E.New("invalid TC chain")
			}
			f.chain = binary.NativeEndian.Uint32(attr.Value)
		}
	}
	if kind != "bpf" {
		return f, false, nil
	}
	f.options, err = nl.ParseRouteAttr(options)
	if err != nil {
		return f, false, err
	}
	for _, attr := range f.options {
		switch attr.Attr.Type {
		case nl.TCA_BPF_NAME:
			f.name = strings.TrimRight(string(attr.Value), "\x00")
		case nl.TCA_BPF_ID, nl.TCA_BPF_FLAGS:
			if len(attr.Value) != 4 {
				return f, false, E.New("invalid TC BPF attribute")
			}
			value := binary.NativeEndian.Uint32(attr.Value)
			if attr.Attr.Type == nl.TCA_BPF_ID {
				f.id = value
			} else {
				f.flags = value
			}
		case nl.TCA_BPF_TAG:
			f.tag = hex.EncodeToString(attr.Value)
		}
	}
	return f, f.flags == nl.TCA_BPF_FLAG_ACT_DIRECT && f.id != 0, nil
}

func currentTetherTCFilter(key tetherTCKey) (tetherTCFilter, bool, error) {
	filters, err := listTetherTCFilters(int(key.link))
	if tetherTCGone(err) {
		return tetherTCFilter{}, false, nil
	}
	if err != nil {
		return tetherTCFilter{}, false, err
	}
	for _, f := range filters {
		if f.key() == key {
			return f, true, nil
		}
	}
	return tetherTCFilter{}, false, nil
}

// Preserve the chain and writable options rather than relying on FilterList,
// which does not expose chain IDs or BPF general flags in our netlink version.
func (f tetherTCFilter) replace(fd int, name string) error {
	if len(name) >= 256 {
		return E.New("tethering TC recovery name is too long")
	}
	candidate, found, err := currentTetherTCFilter(f.key())
	if err != nil {
		return err
	}
	if !found {
		return unix.ENOENT
	}
	if candidate.id != f.id || candidate.name != f.name || candidate.tag != f.tag {
		return unix.ESTALE
	}
	f = candidate
	req := nl.NewNetlinkRequest(unix.RTM_NEWTFILTER, unix.NLM_F_ACK)
	req.AddData(&f.message)
	req.AddData(nl.NewRtAttr(nl.TCA_KIND, nl.ZeroTerminated("bpf")))
	req.AddData(nl.NewRtAttr(unix.TCA_CHAIN, nl.Uint32Attr(f.chain)))
	options := nl.NewRtAttr(nl.TCA_OPTIONS, nil)
	for _, attr := range f.options {
		switch attr.Attr.Type {
		case nl.TCA_BPF_FD, nl.TCA_BPF_NAME, nl.TCA_BPF_ID, nl.TCA_BPF_TAG:
			continue
		case nl.TCA_BPF_CLASSID, nl.TCA_BPF_FLAGS:
			options.AddRtAttr(int(attr.Attr.Type), attr.Value)
		case nl.TCA_BPF_FLAGS_GEN:
			if len(attr.Value) != 4 {
				return E.New("invalid TC BPF general flags")
			}
			flags := binary.NativeEndian.Uint32(attr.Value)
			if flags&2 != 0 { // TCA_CLS_FLAGS_SKIP_SW
				return E.New("cannot pause a hardware-only tethering filter")
			}
			// IN_HW and NOT_IN_HW are dump-only flags.
			options.AddRtAttr(nl.TCA_BPF_FLAGS_GEN, nl.Uint32Attr(flags&1))
		default:
			return E.New("unsupported tethering TC BPF option: ", attr.Attr.Type)
		}
	}
	options.AddRtAttr(nl.TCA_BPF_FD, nl.Uint32Attr(uint32(fd)))
	options.AddRtAttr(nl.TCA_BPF_NAME, nl.ZeroTerminated(name))
	req.AddData(options)
	// Without CREATE, a concurrent netd detach cannot resurrect this filter.
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}
