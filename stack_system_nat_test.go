package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func TestTCPNatLookupPreservesDestination(t *testing.T) {
	nat := newTCPNatForTest()
	source := netip.MustParseAddrPort("192.0.2.1:10000")
	firstDestination := netip.MustParseAddrPort("198.51.100.1:443")
	secondDestination := netip.MustParseAddrPort("198.51.100.2:443")

	firstPort := nat.Lookup(source, firstDestination, header.TCPFlagSyn)
	secondPort := nat.Lookup(source, secondDestination, header.TCPFlagSyn)
	if firstPort == secondPort {
		t.Fatal("connections to different destinations share a NAT port")
	}
	if currentPort := nat.Lookup(source, firstDestination, header.TCPFlagAck); currentPort != firstPort {
		t.Fatalf("existing mapping changed from %d to %d", firstPort, currentPort)
	}
}

func TestTCPNatLookupReclaimsExpiredAndClosedPorts(t *testing.T) {
	const firstNATPort = 10000
	now := time.Now()
	nat := newTCPNatForTest()
	sourceAddress := netip.MustParseAddr("192.0.2.1")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	for natPort := firstNATPort; natPort <= 65535; natPort++ {
		source := netip.AddrPortFrom(sourceAddress, uint16(natPort))
		session := &TCPSession{
			Source:      source,
			Destination: destination,
			LastActive:  now,
		}
		nat.addrMap[tcpNatKey{Source: source, Destination: destination}] = uint16(natPort)
		nat.portMap[uint16(natPort)] = session
	}

	newSource := netip.MustParseAddrPort("192.0.2.2:9999")
	newDestination := netip.MustParseAddrPort("203.0.113.1:443")
	if natPort := nat.Lookup(newSource, newDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed non-expired NAT port %d", natPort)
	}

	// An established session stays live past the transitory timeout.
	establishedSession := nat.portMap[firstNATPort]
	establishedSession.established = true
	establishedSession.LastActive = now.Add(-tcpTransitoryTimeout - time.Second)
	if natPort := nat.Lookup(newSource, newDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed established NAT port %d before established timeout", natPort)
	}

	// A half-closed session expires on the transitory timeout.
	establishedSession.finForward = true
	expiredKey := tcpNatKey{
		Source:      establishedSession.Source,
		Destination: establishedSession.Destination,
	}
	if natPort := nat.Lookup(newSource, newDestination, header.TCPFlagSyn); natPort != firstNATPort {
		t.Fatalf("expected expired half-closed NAT port %d, got %d", firstNATPort, natPort)
	}
	if _, loaded := nat.addrMap[expiredKey]; loaded {
		t.Fatal("expired address mapping was not removed")
	}
	if natPort := nat.addrMap[tcpNatKey{Source: newSource, Destination: newDestination}]; natPort != firstNATPort {
		t.Fatalf("new address mapping uses NAT port %d", natPort)
	}

	// A transitory session is not expired at 2 minutes, but expires past tcpTransitoryTimeout.
	transitoryPort := uint16(firstNATPort + 2)
	transitorySession := nat.portMap[transitoryPort]
	transitorySession.LastActive = now.Add(-2 * time.Minute)
	transitorySource := netip.MustParseAddrPort("192.0.2.2:9997")
	transitoryDestination := netip.MustParseAddrPort("203.0.113.3:443")
	if natPort := nat.Lookup(transitorySource, transitoryDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed transitory NAT port %d before transitory timeout", natPort)
	}
	transitorySession.LastActive = now.Add(-tcpTransitoryTimeout - time.Second)
	if natPort := nat.Lookup(transitorySource, transitoryDestination, header.TCPFlagSyn); natPort != transitoryPort {
		t.Fatalf("expected expired transitory NAT port %d, got %d", transitoryPort, natPort)
	}

	// RST followed by a late FIN keeps the session closed and reclaimable under exhaustion.
	closedPort := uint16(firstNATPort + 1)
	closedKey := tcpNatKey{
		Source:      nat.portMap[closedPort].Source,
		Destination: nat.portMap[closedPort].Destination,
	}
	anotherSource := netip.MustParseAddrPort("192.0.2.2:9998")
	anotherDestination := netip.MustParseAddrPort("203.0.113.2:443")
	if natPort := nat.Lookup(anotherSource, anotherDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed open NAT port %d", natPort)
	}
	if nat.LookupBack(closedPort, header.TCPFlagRst) == nil {
		t.Fatal("failed to look up NAT session")
	}
	if nat.LookupBack(closedPort, header.TCPFlagFin) == nil {
		t.Fatal("failed to observe late FIN on closed NAT session")
	}
	if !nat.portMap[closedPort].closed {
		t.Fatal("late FIN reopened a session closed by RST")
	}
	if natPort := nat.Lookup(anotherSource, anotherDestination, header.TCPFlagSyn); natPort != closedPort {
		t.Fatalf("expected closed NAT port %d, got %d", closedPort, natPort)
	}
	if _, loaded := nat.addrMap[closedKey]; loaded {
		t.Fatal("closed address mapping was not removed")
	}

	// An established session stays live just below tcpEstablishedTimeout and expires past it.
	estPort := uint16(firstNATPort + 3)
	estSession := nat.portMap[estPort]
	estSession.established = true
	estSession.LastActive = now.Add(-tcpEstablishedTimeout + time.Minute)
	estSource := netip.MustParseAddrPort("192.0.2.2:9996")
	estDestination := netip.MustParseAddrPort("203.0.113.4:443")
	if natPort := nat.Lookup(estSource, estDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed established NAT port %d before established timeout", natPort)
	}
	estSession.LastActive = now.Add(-tcpEstablishedTimeout - time.Second)
	if natPort := nat.Lookup(estSource, estDestination, header.TCPFlagSyn); natPort != estPort {
		t.Fatalf("expected expired established NAT port %d, got %d", estPort, natPort)
	}

	// A closed session stays non-expired before tcpClosingTimeout and expires past it (periodic cleanup path).
	closedExpirySession := &TCPSession{
		LastActive: now.Add(-tcpClosingTimeout + time.Second),
		closed:     true,
	}
	if closedExpirySession.expiredLocked(now) {
		t.Fatal("closed session expired before tcpClosingTimeout")
	}
	closedExpirySession.LastActive = now.Add(-tcpClosingTimeout - time.Second)
	if !closedExpirySession.expiredLocked(now) {
		t.Fatal("closed session did not expire after tcpClosingTimeout")
	}
}

func newTCPNatForTest() *TCPNat {
	return &TCPNat{
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
}
