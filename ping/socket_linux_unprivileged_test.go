package ping

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

func TestUnprivilegedConnPruneExpiredMappings(t *testing.T) {
	now := time.Unix(100, 0)
	conn := &UnprivilegedConn{
		idleTimeout: time.Second,
		mapping: map[uint16]*unprivilegedConnEntry{
			1: {lastUsed: now.Add(-2 * time.Second)},
			2: {lastUsed: now},
		},
	}

	conn.mappingAccess.Lock()
	conn.pruneExpiredMappingsLocked(now)
	conn.mappingAccess.Unlock()

	require.NotContains(t, conn.mapping, uint16(1))
	require.Contains(t, conn.mapping, uint16(2))
}

func TestUnprivilegedConnEvictOldestMapping(t *testing.T) {
	now := time.Unix(100, 0)
	conn := &UnprivilegedConn{
		mapping: make(map[uint16]*unprivilegedConnEntry),
	}
	for i := range maxUnprivilegedConnMappings {
		conn.mapping[uint16(i)] = &unprivilegedConnEntry{
			lastUsed: now.Add(time.Duration(i) * time.Second),
		}
	}

	conn.mappingAccess.Lock()
	conn.evictOldestMappingLocked()
	conn.mappingAccess.Unlock()

	require.Len(t, conn.mapping, maxUnprivilegedConnMappings-1)
	require.NotContains(t, conn.mapping, uint16(0))
	require.Contains(t, conn.mapping, uint16(maxUnprivilegedConnMappings-1))
}

func TestUnprivilegedConnEvictionStopsBlockedResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	sender, err := net.DialUDP("udp4", nil, socket.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer sender.Close()
	conn := &UnprivilegedConn{
		ctx:         ctx,
		cancel:      cancel,
		destination: netip.MustParseAddr("192.0.2.1"),
		receiveChan: make(chan *unprivilegedResponse),
		mapping:     make(map[uint16]*unprivilegedConnEntry),
	}
	entry := &unprivilegedConnEntry{conn: socket, lastUsed: time.Unix(100, 0), done: make(chan struct{})}
	conn.mapping[1] = entry
	exited := make(chan struct{})
	go func() {
		conn.fetchResponse(entry, 1)
		close(exited)
	}()
	// The first reply shows that responses are delivered; the second leaves the
	// goroutine blocked on a reader that stopped reading.
	reply := make([]byte, header.ICMPv4MinimumSize)
	for range 2 {
		_, err = sender.Write(reply)
		require.NoError(t, err)
	}
	select {
	case response := <-conn.receiveChan:
		response.Buffer.Release()
		response.Cmsg.Release()
	case <-time.After(5 * time.Second):
		t.Fatal("response was not delivered")
	}
	time.Sleep(100 * time.Millisecond)

	conn.mappingAccess.Lock()
	for identifier := uint16(2); len(conn.mapping) < maxUnprivilegedConnMappings; identifier++ {
		conn.mapping[identifier] = &unprivilegedConnEntry{lastUsed: entry.lastUsed.Add(time.Second)}
	}
	conn.evictOldestMappingLocked()
	conn.mappingAccess.Unlock()
	require.NotContains(t, conn.mapping, uint16(1))

	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("response goroutine of an evicted mapping is still blocked")
	}
}
