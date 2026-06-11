package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var (
	ErrDrop   = E.New("drop by rule")
	ErrReset  = E.New("reset by rule")
	ErrBypass = E.New("bypass by rule")
)

type Stack interface {
	Start() error
	Close() error
}

type StackOptions struct {
	Context                context.Context
	Tun                    Tun
	TunOptions             Options
	UDPTimeout             time.Duration
	ICMPTimeout            time.Duration
	Handler                Handler
	Logger                 logger.Logger
	ForwarderBindInterface bool
	IncludeAllNetworks     bool
	InterfaceFinder        control.InterfaceFinder
}

func NewStack(
	stack string,
	options StackOptions,
) (Stack, error) {
	switch stack {
	case "":
		if options.IncludeAllNetworks {
			return NewGVisor(options)
		} else if WithGVisor && !options.TunOptions.GSO {
			return NewMixed(options)
		} else {
			return NewSystem(options)
		}
	case "gvisor":
		return NewGVisor(options)
	case "mixed":
		if options.IncludeAllNetworks {
			return nil, ErrIncludeAllNetworks
		}
		return NewMixed(options)
	case "system":
		if options.IncludeAllNetworks {
			return nil, ErrIncludeAllNetworks
		}
		return NewSystem(options)
	default:
		return nil, E.New("unknown stack: ", stack)
	}
}

func localDNSServerAddresses(options Options) (inet4Addresses, inet6Addresses []netip.Addr) {
	if options.DNSModeOrDefault() == DNSModeDisabled {
		return
	}
	if inet4DNSAddresses, err := options.Inet4DNSAddress(); err == nil {
		for _, address := range inet4DNSAddresses {
			if prefixListContains(options.Inet4Address, address) {
				inet4Addresses = appendAddress(inet4Addresses, address)
			}
		}
	}
	if inet6DNSAddresses, err := options.Inet6DNSAddress(); err == nil {
		for _, address := range inet6DNSAddresses {
			if prefixListContains(options.Inet6Address, address) {
				inet6Addresses = appendAddress(inet6Addresses, address)
			}
		}
	}
	return
}

func appendAddress(addresses []netip.Addr, address netip.Addr) []netip.Addr {
	if !address.IsValid() || common.Contains(addresses, address) {
		return addresses
	}
	return append(addresses, address)
}

func prefixListContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func HasNextAddress(prefix netip.Prefix, count int) bool {
	checkAddr := prefix.Addr()
	for range count {
		checkAddr = checkAddr.Next()
	}
	return prefix.Contains(checkAddr)
}

func BroadcastAddr(inet4Address []netip.Prefix) netip.Addr {
	if len(inet4Address) == 0 {
		return netip.Addr{}
	}
	prefix := inet4Address[0]
	var broadcastAddr [4]byte
	binary.BigEndian.PutUint32(broadcastAddr[:], binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())|^binary.BigEndian.Uint32(net.CIDRMask(prefix.Bits(), 32)))
	return netip.AddrFrom4(broadcastAddr)
}
