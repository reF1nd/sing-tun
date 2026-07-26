package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type selectorTestPort struct {
	Port
	count uint16
}

func (*selectorTestPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
}
func (*selectorTestPort) PortMTU() uint32                       { return 1500 }
func (p *selectorTestPort) PortSelectorRange() (uint16, uint16) { return 49152, p.count }
func (*selectorTestPort) AttachReturn(Return) error             { return nil }
func (*selectorTestPort) DetachReturn(Return) error             { return nil }

type selectorTestHandler struct {
	Handler
	port Port
}

func (h *selectorTestHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionFlow, Port: h.port}
}

type selectorTestWriteback struct{ ForwardWriteback }

func (*selectorTestWriteback) ReturnHeadroom() int { return 0 }

func selectorTestDispatcher(t *testing.T, count uint16) (*ForwardDispatcher, *selectorTestPort) {
	t.Helper()
	port := &selectorTestPort{count: count}
	d := NewForwardDispatcher(&selectorTestHandler{port: port}, &selectorTestWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	return d, port
}

func selectorTestPacket(source string) forwardPacket {
	packet := forwardPacket{ipVersion: 4, protocol: uint8(header.TCPProtocolNumber), source: netip.MustParseAddrPort(source), destination: netip.MustParseAddrPort("198.51.100.1:443"), hasFlow: true, tcpFlags: header.TCPFlagSyn}
	if packet.source.Addr().Is6() {
		packet.ipVersion = 6
		packet.destination = netip.MustParseAddrPort("[2001:db8:2::1]:443")
	}
	return packet
}

func selectorTestInstall(t *testing.T, d *ForwardDispatcher, source string) *flowEntry {
	t.Helper()
	packet := selectorTestPacket(source)
	var raw []byte
	var tcp header.TCP
	if packet.ipVersion == 4 {
		raw = make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
		ip := header.IPv4(raw)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(raw)), Protocol: uint8(header.TCPProtocolNumber), TTL: 64, SrcAddr: packet.source.Addr(), DstAddr: packet.destination.Addr()})
		tcp = header.TCP(ip.Payload())
	} else {
		raw = make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
		ip := header.IPv6(raw)
		ip.Encode(&header.IPv6Fields{PayloadLength: header.TCPMinimumSize, TransportProtocol: header.TCPProtocolNumber, HopLimit: 64, SrcAddr: packet.source.Addr(), DstAddr: packet.destination.Addr()})
		tcp = header.TCP(ip.Payload())
	}
	tcp.Encode(&header.TCPFields{SrcPort: packet.source.Port(), DstPort: packet.destination.Port(), SeqNum: 1, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535})
	key := packet.flowKey()
	require.True(t, d.Dispatch(raw))
	d.access.Lock()
	defer d.access.Unlock()
	return d.table[key]
}

func TestForwardNATReclaimsOnExhaustion(t *testing.T) {
	for _, sources := range [][2]string{{"10.0.0.1:49152", "10.0.0.2:49152"}, {"[2001:db8:1::1]:49152", "[2001:db8:1::2]:49152"}} {
		for _, state := range []string{"expired", "closed", "tombstone", "active", "reverse active"} {
			t.Run(sources[0]+"/"+state, func(t *testing.T) {
				d, _ := selectorTestDispatcher(t, 1)

				old := selectorTestInstall(t, d, sources[0])
				require.Equal(t, ActionFlow, old.action)
				oldFlow := old.flow
				oldPacket := selectorTestPacket(sources[0])
				key := oldPacket.flowKey()
				switch state {
				case "expired":
					old.deadline = -1
				case "closed":
					old.flow.CloseFlow()
				case "tombstone":
					old.flow.CloseFlow()
					d.maybeSweep(d.now() + int64(flowSweepInterval))
				case "reverse active":
					old.deadline = -1
					old.flow.lastReverse.Store(d.now())
				}
				current := selectorTestInstall(t, d, sources[1])
				if state == "active" || state == "reverse active" {
					require.Nil(t, current)
					require.Len(t, d.writebackBatch, 1)
					require.Same(t, oldFlow, oldFlow.nat.lookup(oldFlow.reverseKey))
					require.False(t, oldFlow.closed.Load())
					return
				}
				require.Equal(t, ActionFlow, current.action, "reclaim unusable mappings before rejecting a new flow")
				require.Same(t, current.flow, oldFlow.nat.lookup(oldFlow.reverseKey))
				// Cleanup of the old forward entry must not remove the replacement mapping.
				if entry := d.table[key]; entry != nil {
					require.Equal(t, ActionDrop, entry.action)
					require.Nil(t, entry.flow)
					require.Same(t, entry, selectorTestInstall(t, d, sources[0]), "delayed packets must still hit the forward tombstone")
					d.removeEntry(key, entry, FlowCloseTimeout)
				}
				require.Same(t, current.flow, oldFlow.nat.lookup(oldFlow.reverseKey))
			})
		}
	}
}

func TestForwardNATRetriesAfterCapacityReturns(t *testing.T) {
	d, _ := selectorTestDispatcher(t, 1)

	old := selectorTestInstall(t, d, "10.0.0.1:49152")
	selectorTestInstall(t, d, "10.0.0.2:49152")
	require.Len(t, d.writebackBatch, 1, "a full pool must reject the new SYN")
	old.flow.CloseFlow()
	retried := selectorTestInstall(t, d, "10.0.0.2:49152")
	require.NotNil(t, retried)
	require.Equal(t, ActionFlow, retried.action, "temporary capacity failure must not cache a route rejection")
}

func TestForwardNATOldFlowCannotDeleteReplacement(t *testing.T) {
	d, port := selectorTestDispatcher(t, 1)

	packet := selectorTestPacket("10.0.0.1:49152")
	old, result := d.createFlow(&packet, FlowVerdict{Action: ActionFlow, Port: port})
	require.Equal(t, createFlowOK, result)
	old.CloseFlow()
	old.nat.delete(old.reverseKey, old)
	replacement, result := d.createFlow(&packet, FlowVerdict{Action: ActionFlow, Port: port})
	require.Equal(t, createFlowOK, result)
	old.nat.delete(old.reverseKey, old)
	require.Same(t, replacement, old.nat.lookup(old.reverseKey))
}

func TestForwardNATKeepsClosedMappingWhileCapacityAvailable(t *testing.T) {
	d, _ := selectorTestDispatcher(t, 2)

	old := selectorTestInstall(t, d, "10.0.0.1:49152")
	old.flow.CloseFlow()
	current := selectorTestInstall(t, d, "10.0.0.2:49152")
	require.Equal(t, ActionFlow, current.action)
	require.NotEqual(t, old.flow.reverseKey, current.flow.reverseKey)
	require.Same(t, old.flow, old.flow.nat.lookup(old.flow.reverseKey))
}
