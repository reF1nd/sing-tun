package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type TCPNat struct {
	timeout    time.Duration
	portIndex  uint16
	portAccess sync.RWMutex
	addrAccess sync.RWMutex
	addrMap    map[tcpNatKey]uint16
	portMap    map[uint16]*TCPSession
}

type tcpNatKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source            netip.AddrPort
	Destination       netip.AddrPort
	LastActive        time.Time
	activeConnections int
	lastClosed        time.Time
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	natMap := &TCPNat{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(n.timeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	now := time.Now()
	type expiredSession struct {
		port    uint16
		session *TCPSession
	}
	var expired []expiredSession
	n.portAccess.RLock()
	for natPort, session := range n.portMap {
		session.Lock()
		timedOut := now.Sub(session.LastActive) > n.timeout
		session.Unlock()
		if timedOut {
			expired = append(expired, expiredSession{port: natPort, session: session})
		}
	}
	n.portAccess.RUnlock()
	if len(expired) == 0 {
		return
	}
	n.addrAccess.Lock()
	n.portAccess.Lock()
	for _, e := range expired {
		e.session.Lock()
		if now.Sub(e.session.LastActive) > n.timeout {
			delete(n.addrMap, tcpNatKey{Source: e.session.Source, Destination: e.session.Destination})
			delete(n.portMap, e.port)
		}
		e.session.Unlock()
	}
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
}

func (n *TCPNat) Purge() {
	n.addrAccess.Lock()
	n.portAccess.Lock()
	clear(n.addrMap)
	clear(n.portMap)
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	if session != nil {
		session.refresh()
	}
	n.portAccess.RUnlock()
	return session
}

func (s *TCPSession) refresh() {
	s.Lock()
	if time.Since(s.LastActive) > time.Second {
		s.LastActive = time.Now()
	}
	s.Unlock()
}

func (n *TCPNat) refresh(port uint16) {
	n.portAccess.RLock()
	session := n.portMap[port]
	if session != nil {
		session.refresh()
	}
	n.portAccess.RUnlock()
}

func (n *TCPNat) acquire(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	if session != nil {
		session.Lock()
		session.activeConnections++
		session.LastActive = time.Now()
		session.Unlock()
	}
	n.portAccess.RUnlock()
	return session
}

func (n *TCPNat) release(port uint16, session *TCPSession) {
	n.portAccess.RLock()
	if n.portMap[port] == session {
		session.Lock()
		if session.activeConnections > 0 {
			session.activeConnections--
			if session.activeConnections == 0 {
				now := time.Now()
				session.LastActive = now
				session.lastClosed = now
			}
		}
		session.Unlock()
	}
	n.portAccess.RUnlock()
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort) uint16 {
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		n.refresh(port)
		return port
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	port, loaded = n.addrMap[key]
	if loaded {
		n.refresh(port)
		return port
	}
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	nextPort, ok := n.allocatePortLocked(time.Now())
	if !ok {
		return 0
	}
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	n.addrMap[key] = nextPort
	return nextPort
}

func (n *TCPNat) allocatePortLocked(now time.Time) (uint16, bool) {
	var (
		closedPort uint16
		closedAt   time.Time
		closedKey  tcpNatKey
	)
	// Prefer an unused or expired port. A recently closed port is only
	// reclaimed after the entire selector space has been exhausted, preserving
	// the normal timeout grace period for delayed packets.
	for range 65535 - 10000 + 1 {
		nextPort := n.portIndex
		if nextPort == 0 {
			nextPort = 10000
			n.portIndex = 10001
		} else {
			n.portIndex++
		}
		session, occupied := n.portMap[nextPort]
		if !occupied {
			return nextPort, true
		}
		session.Lock()
		expired := now.Sub(session.LastActive) > n.timeout
		if !expired && session.activeConnections == 0 && !session.lastClosed.IsZero() &&
			(closedAt.IsZero() || session.LastActive.Before(closedAt)) {
			closedPort = nextPort
			closedAt = session.LastActive
			closedKey = tcpNatKey{Source: session.Source, Destination: session.Destination}
		}
		if expired {
			delete(n.addrMap, tcpNatKey{Source: session.Source, Destination: session.Destination})
			delete(n.portMap, nextPort)
		}
		session.Unlock()
		if expired {
			return nextPort, true
		}
	}
	if !closedAt.IsZero() {
		delete(n.addrMap, closedKey)
		delete(n.portMap, closedPort)
		return closedPort, true
	}
	return 0, false
}
