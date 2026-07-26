package tun

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestTCPNatLookupPreservesDestination(t *testing.T) {
	nat := newTCPNatForTest(time.Minute)
	source := netip.MustParseAddrPort("192.0.2.1:10000")
	firstDestination := netip.MustParseAddrPort("198.51.100.1:443")
	secondDestination := netip.MustParseAddrPort("198.51.100.2:443")

	firstPort := nat.Lookup(source, firstDestination)
	secondPort := nat.Lookup(source, secondDestination)
	if firstPort == secondPort {
		t.Fatal("connections to different destinations share a NAT port")
	}
	if currentPort := nat.Lookup(source, firstDestination); currentPort != firstPort {
		t.Fatalf("existing mapping changed from %d to %d", firstPort, currentPort)
	}
}

func TestTCPNatLookupReclaimsExpiredAndClosedPorts(t *testing.T) {
	const firstNATPort = 10000
	timeout := time.Minute
	now := time.Now()
	nat := newTCPNatForTest(timeout)
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
	if natPort := nat.Lookup(newSource, newDestination); natPort != 0 {
		t.Fatalf("reclaimed non-expired NAT port %d", natPort)
	}

	expiredSession := nat.portMap[firstNATPort]
	expiredKey := tcpNatKey{
		Source:      expiredSession.Source,
		Destination: expiredSession.Destination,
	}
	expiredSession.LastActive = now.Add(-2 * timeout)
	if natPort := nat.Lookup(newSource, newDestination); natPort != firstNATPort {
		t.Fatalf("expected expired NAT port %d, got %d", firstNATPort, natPort)
	}
	if _, loaded := nat.addrMap[expiredKey]; loaded {
		t.Fatal("expired address mapping was not removed")
	}
	if natPort := nat.addrMap[tcpNatKey{Source: newSource, Destination: newDestination}]; natPort != firstNATPort {
		t.Fatalf("new address mapping uses NAT port %d", natPort)
	}

	activePort := uint16(firstNATPort + 1)
	activeSession := nat.acquire(activePort)
	if activeSession == nil {
		t.Fatal("failed to acquire active NAT session")
	}
	anotherSource := netip.MustParseAddrPort("192.0.2.2:9998")
	anotherDestination := netip.MustParseAddrPort("203.0.113.2:443")
	if natPort := nat.Lookup(anotherSource, anotherDestination); natPort != 0 {
		t.Fatalf("reclaimed in-use NAT port %d", natPort)
	}
	nat.release(activePort, activeSession)
	if natPort := nat.Lookup(anotherSource, anotherDestination); natPort != activePort {
		t.Fatalf("expected closed NAT port %d, got %d", activePort, natPort)
	}
}

func TestTCPNatTimeoutSnapshot(t *testing.T) {
	for _, scenario := range []string{"expired", "refreshed", "reallocated", "reallocated same tuple"} {
		t.Run(scenario, func(t *testing.T) {
			nat := newTCPNatForTest(time.Minute)
			source := netip.MustParseAddrPort("192.0.2.1:10000")
			destination := netip.MustParseAddrPort("198.51.100.1:443")
			port := nat.Lookup(source, destination)
			snapshot := nat.portMap[port]
			snapshot.LastActive = time.Now().Add(-2 * time.Minute)
			now := time.Now()
			current := snapshot
			switch scenario {
			case "refreshed":
				nat.acquire(port)
			case "reallocated", "reallocated same tuple":
				replacementSource := netip.MustParseAddrPort("192.0.2.2:20000")
				nat.portIndex = port
				if nextPort := nat.Lookup(replacementSource, destination); nextPort != port {
					t.Fatalf("expired port was not reused: got %d, want %d", nextPort, port)
				}
				if scenario == "reallocated same tuple" {
					nat.portMap[port].LastActive = snapshot.LastActive
					nat.portIndex = port
					if nextPort := nat.Lookup(source, destination); nextPort != port {
						t.Fatalf("original tuple did not reuse port: got %d, want %d", nextPort, port)
					}
				}
				current = nat.portMap[port]
			}
			// The timeout scan retained snapshot before a refresh or allocation
			// could acquire the map locks. Complete that scan using its old time.
			nat.addrAccess.Lock()
			nat.portAccess.Lock()
			nat.removeExpiredSessionLocked(port, snapshot, now)
			nat.portAccess.Unlock()
			nat.addrAccess.Unlock()
			key := tcpNatKey{Source: current.Source, Destination: current.Destination}
			if scenario == "expired" {
				if len(nat.portMap) != 0 || len(nat.addrMap) != 0 {
					t.Fatal("expired mapping was not removed")
				}
				return
			}
			if nat.portMap[port] != current {
				t.Fatal("stale timeout snapshot deleted the current port mapping")
			}
			if mappedPort, exists := nat.addrMap[key]; !exists || mappedPort != port {
				t.Fatal("stale timeout snapshot deleted the current address mapping")
			}
		})
	}
}

func TestTCPNatConcurrentAcquireRelease(t *testing.T) {
	nat := newTCPNatForTest(time.Hour)
	source := netip.MustParseAddrPort("192.0.2.1:10000")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	natPort := nat.Lookup(source, destination)

	const (
		workers    = 8
		iterations = 1000
	)
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for range workers {
		go func() {
			defer waitGroup.Done()
			for range iterations {
				session := nat.acquire(natPort)
				if session == nil {
					t.Error("failed to acquire NAT session")
					return
				}
				if nat.LookupBack(natPort) == nil {
					t.Error("failed to look up NAT session")
					return
				}
				nat.release(natPort, session)
			}
		}()
	}
	waitGroup.Wait()

	session := nat.portMap[natPort]
	session.Lock()
	defer session.Unlock()
	if session.activeConnections != 0 {
		t.Fatalf("%d active connections remain", session.activeConnections)
	}
	if session.lastClosed.IsZero() {
		t.Fatal("closed session was not marked reclaimable")
	}
}

func newTCPNatForTest(timeout time.Duration) *TCPNat {
	return &TCPNat{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
}
