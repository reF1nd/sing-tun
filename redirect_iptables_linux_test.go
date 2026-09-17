//go:build linux && !android

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ranges"

	"golang.org/x/sys/unix"
)

// Run with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN.
// Each case runs in its own network namespace, leaving host rules untouched.
func TestAndroidVPNBypassNAT(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires iptables, iproute2 and network namespace privileges")
	}
	if scenario := os.Getenv("SING_TUN_TEST_IPTABLES_CASE"); scenario != "" {
		testAndroidVPNBypassNAT(t, scenario)
		return
	}
	for _, scenario := range []string{"unchanged", "clear", "qos", "unmarked", "outside-prefix", "tun-output"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestAndroidVPNBypassNAT$", "-test.v")
			command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE="+scenario)
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated NAT test: %v\n%s", err, output)
			}
		})
	}
}

// Run with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN.
// The redirect port has no listener, so an intercepted packet is dropped by TPROXY.
func TestIPTablesTProxyLinkLocal(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires ip6tables, iproute2 and network namespace privileges")
	}
	if scenario := os.Getenv("SING_TUN_TEST_IPTABLES_CASE"); scenario != "" {
		testIPTablesTProxyLinkLocal(t, os.Getenv("SING_TUN_TEST_IPTABLES_MODE"), scenario)
		return
	}
	for _, mode := range []string{"vpn-service", "standalone"} {
		for _, scenario := range []string{"outbound", "inbound", "stale-outbound", "global-outbound"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				command := exec.Command(os.Args[0], "-test.run=^TestIPTablesTProxyLinkLocal$", "-test.v")
				command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_MODE="+mode, "SING_TUN_TEST_IPTABLES_CASE="+scenario)
				command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("isolated TPROXY test: %v\n%s", err, output)
				}
			})
		}
	}
}

func testIPTablesTProxyLinkLocal(t *testing.T, mode string, scenario string) {
	t.Helper()
	standalone := mode == "standalone"
	run := func(args ...string) {
		t.Helper()
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
	}
	peer := "sing-tun-test-" + mode + "-" + scenario
	run("ip", "netns", "add", peer)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", peer).Run()
	})
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "vpn0", "type", "dummy")
	run("ip", "link", "set", "vpn0", "up")
	run("ip", "link", "add", "local0", "type", "veth", "peer", "name", "peer0", "netns", peer)
	run("ip", "addr", "add", "fe80::1/64", "dev", "local0", "nodad")
	if scenario == "global-outbound" {
		run("ip", "addr", "add", "2001:db8:cafe::1/64", "dev", "local0", "nodad")
	}
	run("ip", "link", "set", "local0", "up")
	run("ip", "-n", peer, "addr", "add", "fe80::2/64", "dev", "peer0", "nodad")
	if scenario == "global-outbound" {
		run("ip", "-n", peer, "addr", "add", "2001:db8:cafe::2/64", "dev", "peer0", "nodad")
	}
	run("ip", "-n", peer, "link", "set", "peer0", "up")

	redirect := &autoRedirect{
		tunOptions: &Options{
			Name: "vpn0", Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
			AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMark,
		},
		androidVPNService: !standalone, enableIPv6: standalone, tableName: "tp-test", customRedirectPort: 12345,
		interfaceFinder: control.NewDefaultInterfaceFinder(),
	}
	if scenario != "stale-outbound" && scenario != "global-outbound" {
		localAddresses, err := redirect.findLocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		for _, prefix := range localAddresses {
			if prefix.Addr().IsLinkLocalUnicast() {
				t.Fatalf("findLocalAddresses unexpectedly included link-local prefix %s", prefix)
			}
		}
		redirect.localAddresses = localAddresses
	}
	if scenario == "global-outbound" && standalone {
		// Exclude the test UID in standalone mode so the local outbound socket
		// carries neither outputMark nor connmark, matching an excluded local
		// flow whose reply relies on PREROUTING --ctdir REPLY instead of connmark.
		uid := uint32(os.Getuid())
		redirect.tunOptions.ExcludeUID = []ranges.Range[uint32]{{Start: uid, End: uid}}
	}
	if err := redirect.setupIPTablesForFamily(&iptablesFamily{path: "ip6tables", isIPv6: true, tproxy: true}); err != nil {
		t.Fatal(err)
	}
	if scenario == "global-outbound" {
		// On Android, iptablesFillLocalChain omits the --dst-type LOCAL fallback.
		// Remove it here so the test proves --ctdir REPLY itself protects replies.
		for _, chain := range redirect.iptablesLocalChains {
			if chain.table == iptablesTableMangle && chain.hook == iptablesHookPrerouting {
				run("ip6tables", "-t", chain.table, "-D", chain.name, "-m", "addrtype", "--dst-type", "LOCAL,MULTICAST", "-j", "RETURN")
			}
		}
	}
	// Standalone rules have no VpnService gate on the output chain, so
	// marked packets follow the policy routes to the TPROXY chain.
	if standalone {
		if err := redirect.setupRedirectRoutes(); err != nil {
			t.Fatal(err)
		}
	}

	var (
		listenAddress = "[fe80::2%peer0]:43210"
		dialAddress   = "[fe80::2%local0]:43210"
		listenIn      = peer
		dialIn        = ""
	)
	switch scenario {
	case "inbound":
		listenAddress, dialAddress = "[fe80::1%local0]:43210", "[fe80::1%peer0]:43210"
		listenIn, dialIn = "", peer
	case "global-outbound":
		listenAddress, dialAddress = "[2001:db8:cafe::2]:43210", "[2001:db8:cafe::2]:43210"
		listenIn, dialIn = peer, ""
	}
	inNamespace := func(name string, block func() error) error {
		if name == "" {
			return block()
		}
		return runInNetworkNamespace(name, block)
	}
	var listener net.Listener
	err := inNamespace(listenIn, func() (err error) {
		listener, err = net.Listen("tcp6", listenAddress)
		return
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	dialEcho := func(timeout time.Duration) error {
		var conn net.Conn
		dialErr := inNamespace(dialIn, func() (err error) {
			dialer := net.Dialer{Timeout: timeout}
			conn, err = dialer.Dial("tcp6", dialAddress)
			return
		})
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		payload := []byte("link-local")
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		echoed := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echoed); err != nil {
			return err
		}
		if !bytes.Equal(echoed, payload) {
			return errors.New("echo payload mismatch")
		}
		return nil
	}
	if err := dialEcho(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	if scenario == "global-outbound" {
		output, err := exec.Command("ip6tables", "-t", "mangle", "-L", redirect.tableName+"-prerouting-tproxy", "-v", "-n", "-x").CombinedOutput()
		if err != nil {
			t.Fatalf("list prerouting-tproxy counters: %v\n%s", err, output)
		}
		var replyPackets uint64
		var foundReplyRule bool
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "ctdir REPLY") && strings.Contains(line, "RETURN") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					replyPackets, err = strconv.ParseUint(fields[0], 10, 64)
					if err != nil {
						t.Fatalf("parse reply rule packet counter %q: %v", line, err)
					}
					foundReplyRule = true
					break
				}
			}
		}
		if !foundReplyRule {
			t.Fatalf("prerouting-tproxy missing --ctdir REPLY RETURN rule:\n%s", output)
		}
		if replyPackets == 0 {
			t.Fatalf("expected --ctdir REPLY RETURN rule to match reply packets, got 0:\n%s", output)
		}
		// Control check: deleting the --ctdir REPLY rule must cause TPROXY to drop replies.
		run("ip6tables", "-t", "mangle", "-D", redirect.tableName+"-prerouting-tproxy", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN")
		if err := dialEcho(500 * time.Millisecond); err == nil {
			t.Fatal("global-outbound unexpectedly succeeded after removing --ctdir REPLY RETURN rule")
		}
	}
}

type bypassAutoRedirectHandler struct {
	AutoRedirectHandler
	bypassPort uint16
	rejectPort uint16
	bypassHits atomic.Int32
	rejectHits atomic.Int32
}

func (h *bypassAutoRedirectHandler) JudgeFlow(protocol uint8, source netip.AddrPort, destination netip.AddrPort, _ []byte) FlowVerdict {
	if protocol == uint8(unix.IPPROTO_TCP) {
		switch destination.Port() {
		case h.bypassPort:
			h.bypassHits.Add(1)
			return FlowVerdict{Action: ActionBypass}
		case h.rejectPort:
			h.rejectHits.Add(1)
			return FlowVerdict{Action: ActionReject}
		}
	}
	return FlowVerdict{Action: ActionBypass}
}

// Run with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN.
// Verifies that a TCP connection picked up mid-stream after iptables/conntrack
// setup reaches NFQUEUE for a bypass/reject verdict while bypassed replies take
// the PREROUTING --ctdir REPLY return path without hitting TPROXY.
func TestIPTablesMidstreamBypassTProxyReply(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires ip6tables, iproute2 and network namespace privileges")
	}
	if os.Getenv("SING_TUN_TEST_IPTABLES_CASE") == "midstream" {
		testIPTablesMidstreamBypassTProxyReply(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestIPTablesMidstreamBypassTProxyReply$", "-test.v")
	command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE=midstream")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated midstream TPROXY test: %v\n%s", err, output)
	}
}

func testIPTablesMidstreamBypassTProxyReply(t *testing.T) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
	}
	peer := "sing-tun-test-midstream-tproxy"
	run("ip", "netns", "add", peer)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", peer).Run()
	})
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "vpn0", "type", "dummy")
	run("ip", "link", "set", "vpn0", "up")
	run("ip", "link", "add", "local0", "type", "veth", "peer", "name", "peer0", "netns", peer)
	run("ip", "addr", "add", "2001:db8:cafe::1/64", "dev", "local0", "nodad")
	run("ip", "link", "set", "local0", "up")
	run("ip", "-n", peer, "addr", "add", "2001:db8:cafe::2/64", "dev", "peer0", "nodad")
	run("ip", "-n", peer, "link", "set", "peer0", "up")

	startEchoListener := func(addr string) net.Listener {
		t.Helper()
		var listener net.Listener
		if err := runInNetworkNamespace(peer, func() (err error) {
			listener, err = net.Listen("tcp6", addr)
			return
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			for {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					_, _ = io.Copy(conn, conn)
				}(conn)
			}
		}()
		return listener
	}
	startEchoListener("[2001:db8:cafe::2]:43210")
	startEchoListener("[2001:db8:cafe::2]:43211")

	roundTrip := func(conn net.Conn, payload string, timeout time.Duration) error {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if _, err := conn.Write([]byte(payload)); err != nil {
			return err
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		if string(buf) != payload {
			return errors.New("echo payload mismatch")
		}
		return nil
	}

	// Establish both connections before any conntrack/iptables rule exists in this
	// namespace so subsequent segments are picked up mid-stream (non-SYN, ctstate NEW).
	connBypass, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp6", "[2001:db8:cafe::2]:43210")
	if err != nil {
		t.Fatal(err)
	}
	defer connBypass.Close()
	if err := roundTrip(connBypass, "before", 3*time.Second); err != nil {
		t.Fatalf("pre-setup bypass echo failed: %v", err)
	}

	connReject, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp6", "[2001:db8:cafe::2]:43211")
	if err != nil {
		t.Fatal(err)
	}
	defer connReject.Close()
	if err := roundTrip(connReject, "before", 3*time.Second); err != nil {
		t.Fatalf("pre-setup reject echo failed: %v", err)
	}

	handler := &bypassAutoRedirectHandler{bypassPort: 43210, rejectPort: 43211}
	redirect := &autoRedirect{
		tunOptions: &Options{
			Name:                   "vpn0",
			Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
			AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMark,
		},
		handler:            handler,
		logger:             logger.NOP(),
		enableIPv6:         true,
		tableName:          "ms-test",
		customRedirectPort: 12345,
		interfaceFinder:    control.NewDefaultInterfaceFinder(),
	}
	redirect.tunOptions.AutoRedirectInputMarkMask = redirect.packetMarkMask(redirect.tunOptions.AutoRedirectInputMark)
	if err := redirect.startNFQueue(); err != nil {
		t.Fatal(err)
	}
	defer redirect.nfqueueHandler.Close()
	if err := redirect.setupIPTablesForFamily(&iptablesFamily{path: "ip6tables", isIPv6: true, tproxy: true}); err != nil {
		t.Fatal(err)
	}
	for _, chain := range redirect.iptablesLocalChains {
		if chain.table == iptablesTableMangle && chain.hook == iptablesHookPrerouting {
			run("ip6tables", "-t", chain.table, "-D", chain.name, "-m", "addrtype", "--dst-type", "LOCAL,MULTICAST", "-j", "RETURN")
		}
	}
	if err := redirect.setupRedirectRoutes(); err != nil {
		t.Fatal(err)
	}

	if err := roundTrip(connBypass, "midstream", 3*time.Second); err != nil {
		t.Fatalf("midstream bypass echo failed: %v", err)
	}
	if handler.bypassHits.Load() == 0 {
		t.Fatal("expected midstream non-SYN TCP packet to reach NFQUEUE JudgeFlow for bypass")
	}
	if err := roundTrip(connReject, "midstream", time.Second); err == nil {
		t.Fatal("midstream reject connection unexpectedly succeeded")
	}
	if handler.rejectHits.Load() == 0 {
		t.Fatal("expected midstream non-SYN TCP packet to reach NFQUEUE JudgeFlow for reject")
	}

	output, err := exec.Command("ip6tables", "-t", "mangle", "-L", redirect.tableName+"-prerouting-tproxy", "-v", "-n", "-x").CombinedOutput()
	if err != nil {
		t.Fatalf("list prerouting-tproxy counters: %v\n%s", err, output)
	}
	var replyPackets, tproxyPackets uint64
	var foundReplyRule bool
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.Contains(line, "ctdir REPLY") && strings.Contains(line, "RETURN") {
			replyPackets, err = strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				t.Fatalf("parse reply rule packet counter %q: %v", line, err)
			}
			foundReplyRule = true
		} else if len(fields) >= 3 && fields[2] == "TPROXY" {
			n, parseErr := strconv.ParseUint(fields[0], 10, 64)
			if parseErr != nil {
				t.Fatalf("parse TPROXY packet counter %q: %v", line, parseErr)
			}
			tproxyPackets += n
		}
	}
	if !foundReplyRule || replyPackets == 0 {
		t.Fatalf("expected --ctdir REPLY RETURN rule to match midstream reply packets, found=%v packets=%d:\n%s", foundReplyRule, replyPackets, output)
	}
	if tproxyPackets != 0 {
		t.Fatalf("expected 0 packets intercepted by TPROXY for bypassed midstream flow, got %d:\n%s", tproxyPackets, output)
	}
}

func testAndroidVPNBypassNAT(t *testing.T, scenario string) {
	t.Helper()
	run := func(name string, args ...string) {
		t.Helper()
		if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, output)
		}
	}
	run("ip", "link", "set", "lo", "up")
	for _, device := range []struct{ name, address string }{{"vpn0", "172.19.0.1/30"}, {"cell0", "192.0.2.1/24"}} {
		run("ip", "link", "add", device.name, "type", "dummy")
		run("ip", "addr", "add", device.address, "dev", device.name)
		run("ip", "link", "set", device.name, "up")
	}
	outputInterface := "cell0"
	if scenario == "tun-output" {
		outputInterface = "vpn0"
		run("ip", "route", "add", "192.0.2.2/32", "dev", outputInterface)
	}
	redirect := &autoRedirect{
		tunOptions: &Options{
			Name: "vpn0", Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
			AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
		},
		androidVPNService: true, tableName: "nat-test", customRedirectPort: 12345,
	}
	if err := redirect.setupIPTablesForFamily(&iptablesFamily{path: "iptables"}); err != nil {
		t.Fatal(err)
	}
	// Isolate source NAT from interception. Populate the connection mark as
	// pre-match does, then simulate the vendor's later packet-mark rewrite.
	run("iptables", "-t", "nat", "-F", "OUTPUT")
	run("iptables", "-t", "mangle", "-F", "OUTPUT")
	if scenario != "unmarked" {
		run("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "MARK", "--set-xmark", "0x08000000/0x1c000000")
		run("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "CONNMARK", "--save-mark", "--nfmask", "0x1c000000", "--ctmask", "0x1c000000")
	}
	if scenario != "unchanged" {
		mark := "0x13a/0xffffffff"
		if scenario == "clear" {
			mark = "0x0/0xffffffff"
		}
		run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", "MARK", "--set-xmark", mark)
	}
	device, err := net.InterfaceByName(outputInterface)
	if err != nil {
		t.Fatal(err)
	}
	// AF_PACKET observes the actual outgoing IPv4 header after source NAT.
	protocol := int(binary.NativeEndian.Uint16([]byte{0x00, unix.ETH_P_ALL}))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(protocol), Ifindex: device.Index}); err != nil {
		t.Fatal(err)
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}); err != nil {
		t.Fatal(err)
	}
	source := net.ParseIP("172.19.0.1")
	expected := net.ParseIP("192.0.2.1")
	switch scenario {
	case "outside-prefix":
		run("ip", "addr", "add", "198.51.100.1/32", "dev", "vpn0")
		source = net.ParseIP("198.51.100.1")
		expected = source
	case "unmarked", "tun-output":
		expected = source
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: source}, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 43210})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("android-vpn-bypass-nat")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 2048)
	for {
		n, _, readErr := unix.Recvfrom(fd, packet, 0)
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			t.Fatalf("capture outgoing packet: %v", readErr)
		}
		if n < 28 || packet[0]>>4 != 4 || !bytes.HasSuffix(packet[:n], payload) {
			continue
		}
		if actual := net.IP(packet[12:16]); !actual.Equal(expected) {
			t.Fatalf("outgoing source = %s, want %s", actual, expected)
		}
		return
	}
}
