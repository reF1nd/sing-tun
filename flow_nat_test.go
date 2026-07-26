package tun

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

var errTestWriteFailed = errors.New("write failed")

type selectorTestPort struct {
	Port
	count      uint16
	written    [][]byte
	writeErr   error
	returnPath Return
}

func (*selectorTestPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
}
func (*selectorTestPort) PortMTU() uint32                       { return 1500 }
func (p *selectorTestPort) PortSelectorRange() (uint16, uint16) { return 49152, p.count }
func (p *selectorTestPort) AttachReturn(r Return) error         { p.returnPath = r; return nil }
func (p *selectorTestPort) DetachReturn(Return) error           { p.returnPath = nil; return nil }
func (p *selectorTestPort) WritePackets(packets [][]byte) error {
	if p.writeErr != nil {
		return p.writeErr
	}
	for _, packet := range packets {
		p.written = append(p.written, append([]byte(nil), packet...))
	}
	return nil
}

type selectorTestHandler struct {
	Handler
	port Port
}

func (h *selectorTestHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionFlow, Port: h.port}
}

type selectorTestWriteback struct {
	ForwardWriteback
	packets [][]byte
}

func (*selectorTestWriteback) ReturnHeadroom() int { return 0 }
func (w *selectorTestWriteback) WriteReturnPackets(packets [][]byte) error {
	for _, packet := range packets {
		w.packets = append(w.packets, append([]byte(nil), packet...))
	}
	return nil
}

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
		for _, state := range []string{"expired", "aborted", "closed", "tombstone", "active", "reverse active"} {
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
				case "aborted":
					old.flow.CloseFlow()
				case "closed":
					old.flow.close(FlowCloseReset)
				case "tombstone":
					old.flow.close(FlowCloseReset)
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
				if state == "closed" || state == "tombstone" {
					entry := d.table[key]
					require.NotNil(t, entry, "closed flow must retain its forward tombstone")
					require.Equal(t, ActionDrop, entry.action)
					require.Nil(t, entry.flow)
					require.Same(t, entry, selectorTestInstall(t, d, sources[0]), "delayed packets must still hit the forward tombstone")
					d.removeEntry(key, entry, FlowCloseTimeout)
				} else {
					require.Nil(t, d.table[key])
				}
				require.Same(t, current.flow, oldFlow.nat.lookup(oldFlow.reverseKey))
			})
		}
	}
}

func buildTestUDPPacket(source, destination netip.AddrPort, payload []byte) []byte {
	raw := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(raw)),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     source.Addr(),
		DstAddr:     destination.Addr(),
	})
	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{
		SrcPort: source.Port(),
		DstPort: destination.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udp.Payload(), payload)
	return raw
}

func TestForwardNATReclaimDropsStalePendingPackets(t *testing.T) {
	port := &selectorTestPort{count: 1}
	wb := &selectorTestWriteback{}
	d := NewForwardDispatcher(&selectorTestHandler{port: port}, wb, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)

	remote := netip.MustParseAddrPort("198.51.100.1:5353")
	clientA := netip.MustParseAddrPort("10.0.0.1:49152")
	clientB := netip.MustParseAddrPort("10.0.0.2:49152")

	// Client A dispatches a UDP packet (staged in nat.pending, not flushed yet).
	require.True(t, d.Dispatch(buildTestUDPPacket(clientA, remote, []byte("from-A"))))
	keyA := flowKey{protocol: uint8(header.UDPProtocolNumber), source: clientA, destination: remote}
	entryA := d.table[keyA]
	require.NotNil(t, entryA)
	require.NotNil(t, entryA.flow)
	natSelector := entryA.flow.reverseKey.destination.Port()

	// Client A's flow closes before Flush; Client B arrives in the same batch and reclaims the selector.
	entryA.flow.close(FlowCloseReset)
	require.True(t, d.Dispatch(buildTestUDPPacket(clientB, remote, []byte("from-B"))))

	// Flush must only transmit Client B's packet, dropping Client A's stale staged packet.
	d.Flush()
	require.Len(t, port.written, 1)
	sentIP := header.IPv4(port.written[0])
	sentUDP := header.UDP(sentIP.Payload())
	require.Equal(t, []byte("from-B"), sentUDP.Payload())

	// A reply from the remote to the reused selector must route to Client B.
	reply := buildTestUDPPacket(remote, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), natSelector), []byte("reply-B"))
	unconsumed := port.returnPath.ReturnPackets([][]byte{reply})
	require.Empty(t, unconsumed)
	require.Len(t, wb.packets, 1)
	replyIP := header.IPv4(wb.packets[0])
	replyUDP := header.UDP(replyIP.Payload())
	require.Equal(t, clientB.Addr(), replyIP.DestinationAddr())
	require.Equal(t, clientB.Port(), replyUDP.DestinationPort())
	require.Equal(t, []byte("reply-B"), replyUDP.Payload())
}

func buildTestTCPPacketWithPayload(source, destination netip.AddrPort, seq uint32, flags header.TCPFlags, payload []byte) []byte {
	raw := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload))
	ip := header.IPv4(raw)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(raw)),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		SrcAddr:     source.Addr(),
		DstAddr:     destination.Addr(),
	})
	tcp := header.TCP(ip.Payload())
	tcp.Encode(&header.TCPFields{
		SrcPort:    source.Port(),
		DstPort:    destination.Port(),
		SeqNum:     seq,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	copy(tcp.Payload(), payload)
	return raw
}

func TestForwardNATReclaimFlushesPendingTCPRSTBeforeNewSYN(t *testing.T) {
	port := &selectorTestPort{count: 1}
	wb := &selectorTestWriteback{}
	d := NewForwardDispatcher(&selectorTestHandler{port: port}, wb, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)

	remote := netip.MustParseAddrPort("198.51.100.1:443")
	clientA := netip.MustParseAddrPort("10.0.0.1:49152")
	clientB := netip.MustParseAddrPort("10.0.0.2:49152")

	// Establish Client A's TCP flow and flush its SYN.
	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientA, remote, 1, header.TCPFlagSyn, nil)))
	d.Flush()
	port.written = nil

	// In the same batch: Client A sends data (seq=2, 4 bytes) then RST (seq=6),
	// then Client B sends SYN (reclaims selector). Data must precede RST so RCV.NXT matches.
	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientA, remote, 2, header.TCPFlagAck|header.TCPFlagPsh, []byte("data"))))
	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientA, remote, 6, header.TCPFlagRst, nil)))
	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientB, remote, 100, header.TCPFlagSyn, nil)))
	d.Flush()

	require.Len(t, port.written, 3)
	firstTCP := header.TCP(header.IPv4(port.written[0]).Payload())
	secondTCP := header.TCP(header.IPv4(port.written[1]).Payload())
	thirdTCP := header.TCP(header.IPv4(port.written[2]).Payload())
	require.Equal(t, uint32(2), firstTCP.SequenceNumber())
	require.Equal(t, []byte("data"), firstTCP.Payload())
	require.Equal(t, uint32(6), secondTCP.SequenceNumber())
	require.NotZero(t, secondTCP.Flags()&header.TCPFlagRst)
	require.Equal(t, uint32(100), thirdTCP.SequenceNumber())
	require.NotZero(t, thirdTCP.Flags()&header.TCPFlagSyn)
}

func TestForwardNATReclaimSkipsSelectorOnRSTWriteError(t *testing.T) {
	port := &selectorTestPort{count: 1}
	wb := &selectorTestWriteback{}
	d := NewForwardDispatcher(&selectorTestHandler{port: port}, wb, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)

	remote := netip.MustParseAddrPort("198.51.100.1:443")
	clientA := netip.MustParseAddrPort("10.0.0.1:49152")
	clientB := netip.MustParseAddrPort("10.0.0.2:49152")

	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientA, remote, 1, header.TCPFlagSyn, nil)))
	d.Flush()
	port.written = nil

	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientA, remote, 2, header.TCPFlagRst, nil)))
	port.writeErr = errTestWriteFailed
	// Client B must not steal the selector while Client A's RST write fails.
	require.True(t, d.Dispatch(buildTestTCPPacketWithPayload(clientB, remote, 10, header.TCPFlagSyn, nil)))
	require.Len(t, d.writebackBatch, 1)
	keyB := flowKey{protocol: uint8(header.TCPProtocolNumber), source: clientB, destination: remote}
	require.Nil(t, d.table[keyB])
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
