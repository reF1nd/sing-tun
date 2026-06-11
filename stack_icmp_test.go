package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

func TestSystemRespondsToDefaultIPv4DNSEcho(t *testing.T) {
	system := &System{}

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
	system := &System{}

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

func TestLocalDNSServerAddresses(t *testing.T) {
	inet4Prefix := netip.MustParsePrefix("172.18.0.1/29")
	inet6Prefix := netip.MustParsePrefix("fdfe:dcba:9876::1/125")
	tests := []struct {
		name      string
		options   Options
		wantInet4 []netip.Addr
		wantInet6 []netip.Addr
	}{
		{
			name: "default",
			options: Options{
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
			},
			wantInet4: []netip.Addr{netip.MustParseAddr("172.18.0.2")},
			wantInet6: []netip.Addr{netip.MustParseAddr("fdfe:dcba:9876::2")},
		},
		{
			name: "custom addresses in TUN prefixes",
			options: Options{
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
				DNSAddress: []netip.Addr{
					netip.MustParseAddr("172.18.0.3"),
					netip.MustParseAddr("fdfe:dcba:9876::3"),
				},
			},
			wantInet4: []netip.Addr{netip.MustParseAddr("172.18.0.3")},
			wantInet6: []netip.Addr{netip.MustParseAddr("fdfe:dcba:9876::3")},
		},
		{
			name: "external custom addresses",
			options: Options{
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
				DNSAddress: []netip.Addr{
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("2001:4860:4860::8888"),
				},
			},
		},
		{
			name: "disabled",
			options: Options{
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
				DNSMode:      DNSModeDisabled,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inet4Addresses, inet6Addresses := localDNSServerAddresses(test.options)
			require.Equal(t, test.wantInet4, inet4Addresses)
			require.Equal(t, test.wantInet6, inet6Addresses)
		})
	}
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
