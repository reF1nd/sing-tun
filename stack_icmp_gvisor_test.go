//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	gHdr "github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type localICMPTestTun struct {
	Tun
	endpoint *channel.Endpoint
}

func (t *localICMPTestTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}

func (t *localICMPTestTun) WritePacket(*stack.PacketBuffer) (int, error) {
	panic("unexpected direct TUN write for local Echo or dropped packet")
}

func TestGVisorLocalICMPEchoBeforeFlowRouting(t *testing.T) {
	testLocalICMPEchoBeforeFlowRouting(t, func(t *testing.T, options Options, handler *localICMPTestHandler) func([]byte) []byte {
		endpoint := channel.New(16, 1500, "")
		t.Cleanup(endpoint.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		gvisor, err := NewGVisor(StackOptions{
			Context: ctx, Tun: &localICMPTestTun{endpoint: endpoint},
			TunOptions: options, Handler: handler,
			UDPTimeout: time.Minute, ICMPTimeout: time.Minute,
		})
		require.NoError(t, err)
		require.NoError(t, gvisor.Start())
		t.Cleanup(func() { require.NoError(t, gvisor.Close()) })
		return func(raw []byte) []byte {
			protocol := gHdr.IPv4ProtocolNumber
			if raw[0]>>4 == 6 {
				protocol = gHdr.IPv6ProtocolNumber
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			endpoint.InjectInbound(protocol, packet)
			packet.DecRef()
			reply := endpoint.Read()
			if reply == nil {
				return nil
			}
			defer reply.DecRef()
			view := reply.ToView()
			defer view.Release()
			return append([]byte(nil), view.AsSlice()...)
		}
	})
}

func TestMixedLocalICMPEchoBeforeFlowRouting(t *testing.T) {
	testLocalICMPEchoBeforeFlowRouting(t, func(t *testing.T, options Options, handler *localICMPTestHandler) func([]byte) []byte {
		stack, err := NewMixed(StackOptions{TunOptions: options, Handler: handler, Tun: &localICMPTestTun{}})
		require.NoError(t, err)
		mixed := stack.(*Mixed)
		mixed.dispatcher = NewForwardDispatcher(handler, nil, nil, 0, 0)
		t.Cleanup(mixed.dispatcher.Close)
		return func(raw []byte) []byte {
			if mixed.processPacket(raw) {
				return raw
			}
			return nil
		}
	})
}

type gvisorICMPVerdictHandler struct {
	Handler
	verdict FlowVerdict
	judged  atomic.Int32
}

func (h *gvisorICMPVerdictHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	h.judged.Add(1)
	return h.verdict
}

type gvisorICMPRejectPort struct{}

func (gvisorICMPRejectPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}

func (gvisorICMPRejectPort) PortMTU() uint32 {
	return 0
}

func (gvisorICMPRejectPort) AttachReturn(Return) error {
	return nil
}

func (gvisorICMPRejectPort) DetachReturn(Return) error {
	return nil
}

func (gvisorICMPRejectPort) WritePackets([][]byte) error {
	return nil
}

func TestGVisorICMPForwarderLocalAndReject(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		prefix := netip.MustParsePrefix("172.18.0.1/29")
		external := netip.MustParseAddr("8.8.8.8")
		if ipv6 {
			family = "IPv6"
			prefix = netip.MustParsePrefix("fdfe:dcba:9876::1/125")
			external = netip.MustParseAddr("2001:4860:4860::8888")
		}
		source := prefix.Addr().Next().Next().Next()
		dnsAddr := prefix.Addr().Next()

		cases := []struct {
			name        string
			destination netip.Addr
			verdict     FlowVerdict
			icmpCode    uint8
			ipv6Only    bool
			wantJudged  int32
			wantKind    string // "echo", "no-route", "none"
		}{
			{
				name:        "local virtual DNS replies echo without judging",
				destination: dnsAddr,
				verdict:     FlowVerdict{Action: ActionReject},
				wantJudged:  0,
				wantKind:    "echo",
			},
			{
				name:        "external reject sends no-route",
				destination: external,
				verdict:     FlowVerdict{Action: ActionReject},
				wantJudged:  1,
				wantKind:    "no-route",
			},
			{
				name:        "external installFlow failure sends no-route",
				destination: external,
				verdict:     FlowVerdict{Action: ActionFlow, Port: gvisorICMPRejectPort{}},
				wantJudged:  1,
				wantKind:    "no-route",
			},
			{
				name:        "external drop sends no reply",
				destination: external,
				verdict:     FlowVerdict{Action: ActionDrop},
				wantJudged:  1,
				wantKind:    "none",
			},
			{
				name:        "external flow with nil port falls back to echo",
				destination: external,
				verdict:     FlowVerdict{Action: ActionFlow},
				wantJudged:  1,
				wantKind:    "echo",
			},
			{
				name:        "non-zero ICMPv6 echo code is silently consumed",
				destination: external,
				verdict:     FlowVerdict{Action: ActionFlow},
				icmpCode:    1,
				ipv6Only:    true,
				wantJudged:  0,
				wantKind:    "none",
			},
		}

		for _, tc := range cases {
			if tc.ipv6Only && !ipv6 {
				continue
			}
			t.Run(family+"/"+tc.name, func(t *testing.T) {
				endpoint := channel.New(16, 1500, "")
				t.Cleanup(endpoint.Close)
				ipStack, err := newGVisorStack(endpoint, stack.NICOptions{}, false, true)
				require.NoError(t, err)
				t.Cleanup(ipStack.Close)

				handler := &gvisorICMPVerdictHandler{verdict: tc.verdict}
				options := Options{AutoRoute: true}
				if ipv6 {
					options.Inet6Address = []netip.Prefix{prefix}
				} else {
					options.Inet4Address = []netip.Prefix{prefix}
				}
				inet4Local, inet6Local := localICMPAddresses(options)

				forwarder := NewICMPForwarder(ipStack, handler, logger.NOP())
				forwarder.SetLocalAddresses(inet4Local, inet6Local)
				t.Cleanup(func() { require.NoError(t, forwarder.Close()) })
				ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, forwarder.HandlePacket)
				ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, forwarder.HandlePacket)

				var raw []byte
				protocol := gHdr.IPv4ProtocolNumber
				if ipv6 {
					raw = buildICMPv6EchoPacket(source, tc.destination)
					if tc.icmpCode != 0 {
						ipHdr := header.IPv6(raw)
						icmpHdr := header.ICMPv6(ipHdr.Payload())
						icmpHdr.SetCode(header.ICMPv6Code(tc.icmpCode))
						icmpHdr.SetChecksum(0)
						icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
							Header: icmpHdr,
							Src:    source.AsSlice(),
							Dst:    tc.destination.AsSlice(),
						}))
					}
					protocol = gHdr.IPv6ProtocolNumber
				} else {
					raw = buildICMPv4EchoPacket(source, tc.destination)
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
				endpoint.InjectInbound(protocol, pkt)
				pkt.DecRef()

				require.Equal(t, tc.wantJudged, handler.judged.Load())
				reply := endpoint.Read()
				if tc.wantKind == "none" {
					require.Nil(t, reply)
					return
				}
				require.NotNil(t, reply)
				defer reply.DecRef()
				require.Nil(t, endpoint.Read(), "expected no additional reply packet")
				view := reply.ToView()
				defer view.Release()
				got := view.AsSlice()
				if ipv6 {
					ipHdr := header.IPv6(got)
					icmpHdr := header.ICMPv6(ipHdr.Payload())
					switch tc.wantKind {
					case "echo":
						require.Equal(t, tc.destination, ipHdr.SourceAddr())
						require.Equal(t, source, ipHdr.DestinationAddr())
						require.Equal(t, header.ICMPv6EchoReply, icmpHdr.Type())
					case "no-route":
						require.Equal(t, source, ipHdr.DestinationAddr())
						require.Equal(t, header.ICMPv6DstUnreachable, icmpHdr.Type())
						require.Equal(t, header.ICMPv6NetworkUnreachable, icmpHdr.Code())
					}
				} else {
					ipHdr := header.IPv4(got)
					icmpHdr := header.ICMPv4(ipHdr.Payload())
					switch tc.wantKind {
					case "echo":
						require.Equal(t, tc.destination, ipHdr.SourceAddr())
						require.Equal(t, source, ipHdr.DestinationAddr())
						require.Equal(t, header.ICMPv4EchoReply, icmpHdr.Type())
					case "no-route":
						require.Equal(t, source, ipHdr.DestinationAddr())
						require.Equal(t, header.ICMPv4DstUnreachable, icmpHdr.Type())
						require.Equal(t, header.ICMPv4HostUnreachable, icmpHdr.Code())
					}
				}
			})
		}
	}
}

func TestGVisorFilterHandlesTruncatedIPv6PacketWithoutPanic(t *testing.T) {
	endpoint := channel.New(16, 1500, "")
	t.Cleanup(endpoint.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler := &localICMPTestHandler{}
	gvisor, err := NewGVisor(StackOptions{
		Context: ctx,
		Tun:     &localICMPTestTun{endpoint: endpoint},
		TunOptions: Options{
			AutoRoute:    true,
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/125")},
		},
		Handler:     handler,
		UDPTimeout:  time.Minute,
		ICMPTimeout: time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, gvisor.Start())
	t.Cleanup(func() { require.NoError(t, gvisor.Close()) })

	// 40-byte IPv6 header claiming PayloadLength=64 with NextHeader=Destination Options (60)
	// and zero actual payload bytes; must not panic in networkDispatcherFilter.
	truncated := make([]byte, header.IPv6MinimumSize)
	ipHdr := header.IPv6(truncated)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     64,
		TransportProtocol: 60,
		HopLimit:          64,
		SrcAddr:           netip.MustParseAddr("fdfe:dcba:9876::4"),
		DstAddr:           netip.MustParseAddr("fdfe:dcba:9876::2"),
	})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(truncated)})
	require.NotPanics(t, func() {
		endpoint.InjectInbound(gHdr.IPv6ProtocolNumber, pkt)
	})
	pkt.DecRef()
	require.Zero(t, handler.judged)
}
