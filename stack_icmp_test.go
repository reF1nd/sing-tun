package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

func TestSystemRespondsToDefaultIPv4DNSEcho(t *testing.T) {
	stack, err := NewSystem(StackOptions{
		TunOptions: Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.18.0.1/30")},
		},
	})
	require.NoError(t, err)
	system := stack.(*System)
	require.Contains(t, system.inet4LocalAddresses, netip.MustParseAddr("172.18.0.2"))

	packet := buildICMPv4EchoPacket(netip.MustParseAddr("172.18.0.1"), netip.MustParseAddr("172.18.0.2"))
	ipHdr := header.IPv4(packet)
	icmpHdr := header.ICMPv4(ipHdr.Payload())

	writeBack, err := system.processIPv4ICMP(ipHdr, icmpHdr)
	require.NoError(t, err)
	require.True(t, writeBack)
	require.Equal(t, netip.MustParseAddr("172.18.0.2"), ipHdr.SourceAddr())
	require.Equal(t, netip.MustParseAddr("172.18.0.1"), ipHdr.DestinationAddr())
	require.Equal(t, header.ICMPv4EchoReply, icmpHdr.Type())
}

func TestSystemRespondsToDefaultIPv6DNSEcho(t *testing.T) {
	stack, err := NewSystem(StackOptions{
		TunOptions: Options{
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
	})
	require.NoError(t, err)
	system := stack.(*System)
	require.Contains(t, system.inet6LocalAddresses, netip.MustParseAddr("fdfe:dcba:9876::2"))

	packet := buildICMPv6EchoPacket(netip.MustParseAddr("fdfe:dcba:9876::1"), netip.MustParseAddr("fdfe:dcba:9876::2"))
	ipHdr := header.IPv6(packet)
	icmpHdr := header.ICMPv6(ipHdr.Payload())

	writeBack, err := system.processIPv6ICMP(ipHdr, icmpHdr)
	require.NoError(t, err)
	require.True(t, writeBack)
	require.Equal(t, netip.MustParseAddr("fdfe:dcba:9876::2"), ipHdr.SourceAddr())
	require.Equal(t, netip.MustParseAddr("fdfe:dcba:9876::1"), ipHdr.DestinationAddr())
	require.Equal(t, header.ICMPv6EchoReply, icmpHdr.Type())
}

func TestExternalDNSAddressIsNotLocalICMPAddress(t *testing.T) {
	stack, err := NewSystem(StackOptions{
		TunOptions: Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.18.0.1/30")},
			DNSAddress:   []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		},
	})
	require.NoError(t, err)
	system := stack.(*System)
	require.Contains(t, system.inet4LocalAddresses, netip.MustParseAddr("172.18.0.1"))
	require.NotContains(t, system.inet4LocalAddresses, netip.MustParseAddr("172.18.0.2"))
	require.NotContains(t, system.inet4LocalAddresses, netip.MustParseAddr("8.8.8.8"))
}

func buildICMPv4EchoPacket(source netip.Addr, destination netip.Addr) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
		TTL:         64,
	})
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(1)
	icmpHdr.SetSequence(1)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return packet
}

func buildICMPv6EchoPacket(source netip.Addr, destination netip.Addr) []byte {
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	icmpHdr := header.ICMPv6(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv6EchoRequest)
	icmpHdr.SetIdent(1)
	icmpHdr.SetSequence(1)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    source.AsSlice(),
		Dst:    destination.AsSlice(),
	}))
	return packet
}
