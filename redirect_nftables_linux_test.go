//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func runInIsolatedNetNS(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root/CAP_NET_ADMIN for isolated netns nftables test")
	}
	runtime.LockOSThread()
	origFD, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		require.NoError(t, err)
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		_ = unix.Close(origFD)
		runtime.UnlockOSThread()
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("unshare CLONE_NEWNET not permitted: %v", err)
		}
		require.NoError(t, err)
	}
	defer func() {
		restoreErr := unix.Setns(origFD, unix.CLONE_NEWNET)
		_ = unix.Close(origFD)
		if restoreErr == nil {
			runtime.UnlockOSThread()
		}
	}()
	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(lo))
	fn(t)
}

func setContainsPrefixInterval(elements []nftables.SetElement, prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	start := prefix.Addr().AsSlice()
	// nftables interval sets encode [start, endExclusive) with IntervalEnd=true on endExclusive.
	endAddr := prefix.Addr()
	bits := endAddr.BitLen()
	maskBits := prefix.Bits()
	rawEnd := append([]byte(nil), start...)
	// Compute last address in prefix, then add 1 for half-open end.
	for i := maskBits; i < bits; i++ {
		rawEnd[i/8] |= 1 << uint(7-(i%8))
	}
	carry := byte(1)
	for i := len(rawEnd) - 1; i >= 0 && carry > 0; i-- {
		sum := uint16(rawEnd[i]) + uint16(carry)
		rawEnd[i] = byte(sum)
		carry = byte(sum >> 8)
	}
	hasStart := false
	hasEnd := false
	for _, el := range elements {
		if !el.IntervalEnd && bytes.Equal(el.Key, start) {
			hasStart = true
		}
		if el.IntervalEnd && carry == 0 && bytes.Equal(el.Key, rawEnd) {
			hasEnd = true
		}
	}
	return hasStart && (carry != 0 || hasEnd)
}

func TestNFTablesLinkLocalExclusionAndDNSOrder(t *testing.T) {
	for _, fibAddrType := range []bool{true, false} {
		name := "fib_on"
		if !fibAddrType {
			name = "fib_off"
		}
		t.Run(name, func(t *testing.T) {
			runInIsolatedNetNS(t, func(t *testing.T) {
				nft, err := nftables.New()
				require.NoError(t, err)
				defer nft.CloseLasting()

				var emptyRoute, emptyExclude []*netipx.IPSet
				r := &autoRedirect{
					tunOptions: &Options{
						Name:                   "tun0",
						AutoRedirectMarkMode:   true,
						AutoRedirectInputMark:  0x2023,
						AutoRedirectOutputMark: 0x2024,
						DNSMode:                DNSModeHijack,
						Inet4Address:           []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
						Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
					},
					enableIPv4:             true,
					enableIPv6:             true,
					fibAddrType:            fibAddrType,
					tableName:              "sing-tun-test-ll",
					routeAddressSet:        &emptyRoute,
					routeExcludeAddressSet: &emptyExclude,
					redirectServer:         &redirectServer{},
				}
				// Use real bound sockets so Port()/PacketPort() return valid non-zero ports.
				tcpLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6loopback, Port: 0})
				require.NoError(t, err)
				defer tcpLn.Close()
				udpConn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
				require.NoError(t, err)
				defer udpConn.Close()
				r.redirectServer.listener = tcpLn
				r.redirectServer.packetConn = ipv6.NewPacketConn(udpConn)

				table := nft.AddTable(&nftables.Table{
					Name:   r.tableName,
					Family: nftables.TableFamilyINet,
				})
				// Deliberately provide NO link-local prefixes in localAddresses, verifying
				// link-local exclusion does not depend on local address sets.
				localAddresses := []netip.Prefix{
					netip.MustParsePrefix("192.0.2.1/24"),
					netip.MustParsePrefix("2001:db8::1/64"),
				}
				require.NoError(t, r.nftablesCreateLocalAddressSets(nft, table, localAddresses, nil))

				chainPre := nft.AddChain(&nftables.Chain{
					Name:     "prerouting",
					Table:    table,
					Hooknum:  nftables.ChainHookPrerouting,
					Priority: nftables.ChainPriorityNATDest,
					Type:     nftables.ChainTypeNAT,
				})
				require.NoError(t, r.nftablesCreateExcludeRules(nft, table, chainPre))
				require.NoError(t, nft.Flush())

				sets, err := nft.GetSets(table)
				require.NoError(t, err)
				setElems := make(map[string][]nftables.SetElement, len(sets))
				for _, s := range sets {
					elems, err := nft.GetSetElements(s)
					require.NoError(t, err)
					setElems[s.Name] = elems
				}

				rules, err := nft.GetRules(table, chainPre)
				require.NoError(t, err)
				require.NotEmpty(t, rules)

				var (
					dnsLLTCPRedirectIndex = -1
					dnsLLUDPRedirectIndex = -1
					v4ExcludeIndex        = -1
					v6ExcludeIndex        = -1
				)
				wantTCPPort := r.redirectServer.Port()
				wantUDPPort := r.redirectServer.PacketPort()
				v4LL := netip.MustParsePrefix("169.254.0.0/16")
				v6LL := netip.MustParsePrefix("fe80::/10")

				for i, rule := range rules {
					hasV6LLSrc := false
					hasPort53 := false
					hasRedir := false
					hasReturn := false
					var l4Proto uint8
					var redirPort uint16
					var lastMetaKey expr.MetaKey
					var hasLastMeta bool
					var lookupSetName string
					var payloadOffset uint32
					var payloadLen uint32
					var hasTransportLoad bool
					var transportReg uint32
					var transportOffset uint32
					var transportLen uint32

					for _, e := range rule.Exprs {
						switch v := e.(type) {
						case *expr.Meta:
							lastMetaKey = v.Key
							hasLastMeta = true
							hasTransportLoad = false
						case *expr.Payload:
							hasLastMeta = false
							switch v.Base {
							case expr.PayloadBaseNetworkHeader:
								payloadOffset = v.Offset
								payloadLen = v.Len
								hasTransportLoad = false
							case expr.PayloadBaseTransportHeader:
								hasTransportLoad = true
								transportReg = v.DestRegister
								transportOffset = v.Offset
								transportLen = v.Len
							default:
								hasTransportLoad = false
							}
						case *expr.Cmp:
							if hasLastMeta && lastMetaKey == expr.MetaKeyL4PROTO && len(v.Data) == 1 {
								l4Proto = v.Data[0]
							}
							if len(v.Data) == 2 && bytes.Equal(v.Data, []byte{0xfe, 0x80}) && payloadOffset == 8 && payloadLen == 2 {
								hasV6LLSrc = true
							}
							if hasTransportLoad && v.Op == expr.CmpOpEq && v.Register == transportReg &&
								transportOffset == 2 && transportLen == 2 && len(v.Data) == 2 && binary.BigEndian.Uint16(v.Data) == 53 {
								hasPort53 = true
							}
							hasLastMeta = false
							hasTransportLoad = false
						case *expr.Immediate:
							hasLastMeta = false
							hasTransportLoad = false
							if len(v.Data) == 2 {
								redirPort = binary.BigEndian.Uint16(v.Data)
							}
						case *expr.Redir:
							hasLastMeta = false
							hasTransportLoad = false
							hasRedir = true
						case *expr.Lookup:
							hasLastMeta = false
							hasTransportLoad = false
							lookupSetName = v.SetName
						case *expr.Verdict:
							hasLastMeta = false
							hasTransportLoad = false
							if v.Kind == expr.VerdictReturn {
								hasReturn = true
							}
						default:
							hasLastMeta = false
							hasTransportLoad = false
						}
					}
					if hasV6LLSrc && hasPort53 && hasRedir {
						if l4Proto == unix.IPPROTO_TCP && redirPort == wantTCPPort && dnsLLTCPRedirectIndex == -1 {
							dnsLLTCPRedirectIndex = i
						}
						if l4Proto == unix.IPPROTO_UDP && redirPort == wantUDPPort && dnsLLUDPRedirectIndex == -1 {
							dnsLLUDPRedirectIndex = i
						}
					}
					if hasReturn && lookupSetName != "" {
						elems := setElems[lookupSetName]
						if payloadOffset == 16 && payloadLen == 4 && setContainsPrefixInterval(elems, v4LL) && v4ExcludeIndex == -1 {
							v4ExcludeIndex = i
						}
						if payloadOffset == 24 && payloadLen == 16 && setContainsPrefixInterval(elems, v6LL) && v6ExcludeIndex == -1 {
							v6ExcludeIndex = i
						}
					}
				}

				require.NotEqual(t, -1, dnsLLTCPRedirectIndex, "expected IPv6 link-local TCP DNS redirect rule to TCP port %d", wantTCPPort)
				require.NotEqual(t, -1, dnsLLUDPRedirectIndex, "expected IPv6 link-local UDP DNS redirect rule to UDP port %d", wantUDPPort)
				require.NotEqual(t, -1, v4ExcludeIndex, "expected 169.254.0.0/16 destination exclusion rule")
				require.NotEqual(t, -1, v6ExcludeIndex, "expected fe80::/10 destination exclusion rule")
				require.Less(t, dnsLLTCPRedirectIndex, v6ExcludeIndex, "link-local TCP DNS hijack must precede fe80::/10 destination exclusion")
				require.Less(t, dnsLLUDPRedirectIndex, v6ExcludeIndex, "link-local UDP DNS hijack must precede fe80::/10 destination exclusion")
			})
		})
	}
}

func TestNFTablesIPv6LinkLocalDestinationTrafficBypass(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root/CAP_NET_ADMIN for isolated netns nftables traffic test")
	}
	for _, fibAddrType := range []bool{true, false} {
		name := "fib_on"
		if !fibAddrType {
			name = "fib_off"
		}
		t.Run(name, func(t *testing.T) {
			runInIsolatedNetNS(t, func(t *testing.T) {
				// Create a veth pair; put peer in a child netns via another locked goroutine
				// so traffic to peer's fe80:: address actually traverses the output NAT chain.
				lo, err := netlink.LinkByName("lo")
				require.NoError(t, err)
				require.NoError(t, netlink.LinkSetUp(lo))

				veth := &netlink.Veth{
					LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
					PeerName:  "veth1",
				}
				require.NoError(t, netlink.LinkAdd(veth))
				veth0, err := netlink.LinkByName("veth0")
				require.NoError(t, err)
				veth1, err := netlink.LinkByName("veth1")
				require.NoError(t, err)

				// Start peer netns with veth1 listening on its IPv6 link-local address.
				peerReady := make(chan string, 1)
				peerErr := make(chan error, 1)
				peerDone := make(chan struct{})
				peerExited := make(chan struct{})
				defer func() {
					close(peerDone)
					<-peerExited
				}()

				// Open a handle to move veth1 into a separate netns using an unbuffered
				// handoff channel so fd ownership is never lost on early exit/error.
				nsReady := make(chan int)
				linkMoved := make(chan struct{})
				go func() {
					defer close(peerExited)
					// Keep OS thread locked until exit so Go terminates the thread
					// instead of reusing a thread attached to the peer netns.
					runtime.LockOSThread()
					if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
						peerErr <- err
						return
					}
					fd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
					if err != nil {
						peerErr <- err
						return
					}
					select {
					case nsReady <- fd:
					case <-peerDone:
						_ = unix.Close(fd)
						return
					}
					select {
					case <-linkMoved:
					case <-peerDone:
						return
					}
					peerLink, err := netlink.LinkByName("veth1")
					if err != nil {
						peerErr <- err
						return
					}
					if err := netlink.LinkSetUp(peerLink); err != nil {
						peerErr <- err
						return
					}
					addr, _ := netlink.ParseAddr("fe80::2/64")
					addr.Flags = unix.IFA_F_NODAD
					if err := netlink.AddrAdd(peerLink, addr); err != nil {
						peerErr <- err
						return
					}
					ln, err := net.ListenTCP("tcp6", &net.TCPAddr{
						IP:   net.ParseIP("fe80::2"),
						Zone: "veth1",
						Port: 18080,
					})
					if err != nil {
						peerErr <- err
						return
					}
					defer ln.Close()
					peerReady <- "ok"
					go func() {
						<-peerDone
						_ = ln.Close()
					}()
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					_, _ = conn.Write([]byte("DIRECT_PEER"))
				}()

				select {
				case err := <-peerErr:
					t.Fatalf("peer setup failed: %v", err)
				case nsFd := <-nsReady:
					moveErr := netlink.LinkSetNsFd(veth1, nsFd)
					_ = unix.Close(nsFd)
					require.NoError(t, moveErr)
					close(linkMoved)
				}

				require.NoError(t, netlink.LinkSetUp(veth0))
				localAddr, err := netlink.ParseAddr("fe80::1/64")
				require.NoError(t, err)
				localAddr.Flags = unix.IFA_F_NODAD
				require.NoError(t, netlink.AddrAdd(veth0, localAddr))

				select {
				case err := <-peerErr:
					t.Fatalf("peer listen failed: %v", err)
				case <-peerReady:
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for peer link-local listener")
				}

				// Start a mock redirect server that replies "REDIRECTED" if traffic is hijacked.
				redirLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv6unspecified, Port: 0})
				require.NoError(t, err)
				defer redirLn.Close()
				go func() {
					for {
						c, err := redirLn.Accept()
						if err != nil {
							return
						}
						_, _ = c.Write([]byte("REDIRECTED"))
						_ = c.Close()
					}
				}()

				nft, err := nftables.New()
				require.NoError(t, err)
				defer nft.CloseLasting()

				var emptyRoute, emptyExclude []*netipx.IPSet
				r := &autoRedirect{
					tunOptions: &Options{
						Name:                   "tun0",
						AutoRedirectMarkMode:   true,
						AutoRedirectInputMark:  0x2023,
						AutoRedirectOutputMark: 0x2024,
						DNSMode:                DNSModeHijack,
						Inet4Address:           []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
						Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
					},
					enableIPv4:             true,
					enableIPv6:             true,
					fibAddrType:            fibAddrType,
					tableName:              "sing-tun-test-ll-traffic",
					routeAddressSet:        &emptyRoute,
					routeExcludeAddressSet: &emptyExclude,
					redirectServer: &redirectServer{
						listener: redirLn,
					},
				}

				table := nft.AddTable(&nftables.Table{
					Name:   r.tableName,
					Family: nftables.TableFamilyINet,
				})
				// Provide only non-link-local interface address in local set.
				require.NoError(t, r.nftablesCreateLocalAddressSets(nft, table, []netip.Prefix{
					netip.MustParsePrefix("2001:db8::1/64"),
				}, nil))
				chainOut := nft.AddChain(&nftables.Chain{
					Name:     "output",
					Table:    table,
					Hooknum:  nftables.ChainHookOutput,
					Priority: nftables.ChainPriorityMangle,
					Type:     nftables.ChainTypeNAT,
				})
				require.NoError(t, r.nftablesCreateExcludeRules(nft, table, chainOut))
				require.NoError(t, r.nftablesCreateRedirect(nft, table, chainOut))
				require.NoError(t, nft.Flush())

				// Dial peer's fe80::2 on non-DNS port 18080; must reach DIRECT_PEER, not REDIRECTED.
				dialer := net.Dialer{Timeout: 3 * time.Second}
				conn, err := dialer.Dial("tcp6", "[fe80::2%veth0]:18080")
				require.NoError(t, err)
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				got, err := io.ReadAll(conn)
				require.NoError(t, err)
				require.Equal(t, "DIRECT_PEER", string(got))
			})
		})
	}
}
