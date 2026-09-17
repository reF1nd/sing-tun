package tun

import (
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

const (
	vpnServiceTestLocalNetworkTable = "97"
	vpnServiceTestCellularTable     = "1020"
	vpnServiceTestWiFiTable         = "1030"
	vpnServiceTestHotspotTable      = "1085"
	vpnServiceTestClient            = "10.65.121.68"
	vpnServiceTestRemote            = "1.1.1.1"
	vpnServiceTestOutputMark        = "0x8000000"
	vpnServiceTestProtectedOutMark  = "0x8020000"
	vpnServiceTestResetMark         = "0x800000"
	vpnServiceTestMarkMask          = "0xc800000"
)

// Run on Linux with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN,
// using a binary built with GOOS=android CGO_ENABLED=0 go test -c and
// /system/bin/linker64 linked to the host's dynamic loader.
// Each case runs in its own network namespace, leaving host rules untouched.
func TestAndroidVPNServiceLocalNetworkRoutes(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires iproute2 and network namespace privileges")
	}
	if scenario := os.Getenv("SING_TUN_TEST_IPTABLES_CASE"); scenario != "" {
		testAndroidVPNServiceLocalNetworkRoutes(t, scenario)
		return
	}
	for _, scenario := range []string{"hotspot-first", "hotspot-later", "default-network-change", "shared-table", "stale-rules", "bypass-route"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestAndroidVPNServiceLocalNetworkRoutes$", "-test.v")
			command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE="+scenario)
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated route test: %v\n%s", err, output)
			}
		})
	}
}

type vpnServiceRouteTest struct {
	t *testing.T
	r *autoRedirect
}

func (s *vpnServiceRouteTest) ip(args ...string) string {
	s.t.Helper()
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		s.t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func (s *vpnServiceRouteTest) setup() {
	s.t.Helper()
	s.ip("link", "set", "lo", "up")
	for _, name := range []string{"tun0", "rmnet0", "wlan0", "wlan2"} {
		s.ip("link", "add", name, "type", "dummy")
		s.ip("link", "set", name, "up")
	}
	s.ip("addr", "add", "172.18.0.1/30", "dev", "tun0")
	s.ip("addr", "add", "10.83.209.179/29", "dev", "rmnet0")
	s.ip("addr", "add", "192.168.50.2/24", "dev", "wlan0")
	s.ip("addr", "add", "10.65.121.63/24", "dev", "wlan2")
	tunLink, err := netlink.LinkByName("tun0")
	if err != nil {
		s.t.Fatal(err)
	}
	tunTable := strconv.Itoa(tunLink.Attrs().Index + androidRouteTableOffsetFromIndex)
	s.ip("route", "add", "0.0.0.0/1", "dev", "tun0", "table", tunTable)
	s.ip("route", "add", "128.0.0.0/1", "dev", "tun0", "table", tunTable)
	s.ip("route", "add", "default", "via", "10.83.209.180", "dev", "rmnet0", "table", vpnServiceTestCellularTable)
	s.ip("route", "add", "default", "via", "192.168.50.1", "dev", "wlan0", "table", vpnServiceTestWiFiTable)
	s.ip("rule", "add", "pref", "12000", "iif", "tun0", "lookup", vpnServiceTestLocalNetworkTable)
	s.ip("rule", "add", "pref", "13000", "fwmark", "0x0/0x20000", "iif", "lo", "uidrange", "0-99999", "lookup", tunTable)
	s.ip("rule", "add", "pref", "20000", "fwmark", "0x0/0x10000", "lookup", vpnServiceTestLocalNetworkTable)
	s.ip("rule", "add", "pref", "31000", "fwmark", "0x0/0xffff", "iif", "lo", "lookup", vpnServiceTestCellularTable)
	s.r = &autoRedirect{
		tunOptions: &Options{
			Name:                   "tun0",
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("172.18.0.1/30")},
			AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
			AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMark,
		},
		logger:     logger.NOP(),
		enableIPv4: true,
	}
}

func (s *vpnServiceRouteTest) hotspot(action string) {
	s.t.Helper()
	s.ip("route", action, "10.65.121.0/24", "dev", "wlan2", "table", vpnServiceTestHotspotTable)
	s.ip("rule", action, "pref", "20000", "fwmark", "0x0/0x10000", "lookup", vpnServiceTestHotspotTable)
}

func (s *vpnServiceRouteTest) update() {
	s.t.Helper()
	err := s.r.updateAndroidVPNServiceRules()
	if err != nil {
		s.t.Fatal(err)
	}
}

func (s *vpnServiceRouteTest) expectDevice(destination string, mark string, device string) {
	s.t.Helper()
	args := []string{"route", "get", destination}
	if mark != "" {
		args = append(args, "mark", mark)
	}
	output := s.ip(args...)
	if !strings.Contains(output, " dev "+device+" ") {
		s.t.Fatalf("%s with mark %q: expected dev %s, got %s\nrules:\n%s", destination, mark, device, output, s.ip("rule", "show"))
	}
}

func (s *vpnServiceRouteTest) serviceRules() []string {
	s.t.Helper()
	var rules []string
	for line := range strings.SplitSeq(s.ip("rule", "show"), "\n") {
		if strings.HasPrefix(line, "8999:") || strings.HasPrefix(line, "9000:") {
			rules = append(rules, line)
		}
	}
	return rules
}

func testAndroidVPNServiceLocalNetworkRoutes(t *testing.T, scenario string) {
	s := &vpnServiceRouteTest{t: t}
	s.setup()
	switch scenario {
	case "hotspot-first":
		s.hotspot("add")
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestProtectedOutMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestResetMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.r.cleanupAndroidVPNServiceRules()
		if rules := s.serviceRules(); len(rules) != 0 {
			t.Fatalf("rules left after cleanup: %q", rules)
		}
	case "hotspot-later":
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.hotspot("add")
		s.update()
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestProtectedOutMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestResetMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		rules := s.serviceRules()
		s.update()
		if repeated := s.serviceRules(); strings.Join(repeated, "\n") != strings.Join(rules, "\n") {
			t.Fatalf("repeated update changed rules:\n%q\n%q", rules, repeated)
		}
		s.hotspot("del")
		s.update()
		for _, rule := range s.serviceRules() {
			if strings.Contains(rule, "lookup "+vpnServiceTestHotspotTable) {
				t.Fatalf("hotspot rule left after the network went away: %q", rule)
			}
		}
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.r.cleanupAndroidVPNServiceRules()
		if rules = s.serviceRules(); len(rules) != 0 {
			t.Fatalf("rules left after cleanup: %q", rules)
		}
	case "default-network-change":
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.hotspot("add")
		s.update()
		s.ip("rule", "del", "pref", "31000", "fwmark", "0x0/0xffff", "iif", "lo", "lookup", vpnServiceTestCellularTable)
		s.ip("rule", "add", "pref", "31000", "fwmark", "0x0/0xffff", "iif", "lo", "lookup", vpnServiceTestWiFiTable)
		s.update()
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "wlan0")
		s.r.cleanupAndroidVPNServiceRules()
	case "shared-table":
		s.ip("route", "add", "10.65.121.0/24", "dev", "wlan2", "table", vpnServiceTestLocalNetworkTable)
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestProtectedOutMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestResetMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.r.cleanupAndroidVPNServiceRules()
	case "stale-rules":
		// Left by a process that died with other networks available, or by an
		// older build that installed the legacy 0x10000000/0x1c000000 reset
		// rule, so neither rule is installed again and only the stale pass
		// removes them. An unrelated iif-scoped rule using the same mark and
		// mask in a different table must be preserved.
		s.ip("rule", "add", "pref", "8999", "fwmark", vpnServiceTestOutputMark+"/"+vpnServiceTestMarkMask, "iif", "lo", "lookup", vpnServiceTestHotspotTable)
		s.ip("rule", "add", "pref", "9000", "fwmark", vpnServiceTestOutputMark+"/"+vpnServiceTestMarkMask, "iif", "lo", "lookup", vpnServiceTestWiFiTable)
		s.ip("rule", "add", "pref", "9000", "fwmark", "0x10000000/0x1c000000", "iif", "lo", "lookup", "1234")
		s.ip("rule", "add", "pref", "9000", "fwmark", "0x10000000/0x1c000000", "lookup", vpnServiceTestHotspotTable)
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		keptUnrelated := false
		for _, rule := range s.serviceRules() {
			if strings.Contains(rule, "lookup 1234") {
				keptUnrelated = true
				continue
			}
			if strings.Contains(rule, "lookup "+vpnServiceTestHotspotTable) || strings.Contains(rule, "lookup "+vpnServiceTestWiFiTable) || strings.Contains(rule, "0x10000000/0x1c000000") {
				t.Fatalf("stale rule left after setup: %q", rule)
			}
		}
		if !keptUnrelated {
			t.Fatalf("unrelated iif-scoped rule was deleted:\n%q", s.serviceRules())
		}
		s.r.cleanupAndroidVPNServiceRules()
		s.ip("rule", "del", "pref", "9000", "fwmark", "0x10000000/0x1c000000", "iif", "lo", "lookup", "1234")
		if rules := s.serviceRules(); len(rules) != 0 {
			t.Fatalf("rules left after cleanup: %q", rules)
		}
	case "bypass-route":
		s.r.routeAddressSet = func() ([]netip.Prefix, []netip.Prefix, error) {
			return nil, []netip.Prefix{netip.MustParsePrefix("10.65.121.0/24"), netip.MustParsePrefix(vpnServiceTestRemote + "/32")}, nil
		}
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.r.setupBypassRoute()
		if !s.r.bypassRouteActive {
			t.Fatal("bypass route is not active")
		}
		s.expectDevice(vpnServiceTestRemote, "", "rmnet0")
		s.hotspot("add")
		if err := s.r.updateBypassRoute(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestClient, "", "wlan2")
		s.expectDevice(vpnServiceTestRemote, "", "rmnet0")
		s.r.cleanupBypassRoute()
		s.r.cleanupAndroidVPNServiceRules()
	default:
		t.Fatalf("unknown scenario %q", scenario)
	}
}

// Run on Linux with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN,
// using a binary built with GOOS=android CGO_ENABLED=0 go test -c.
// Verifies that standalone IPv6 TCP TPROXY still completes the handshake and
// transfers data when an OEM rule appends CONNMARK 0x30000000/0x30000000 on
// wlan0 OUTPUT (as Xiaomi HyperOS tc_limiter_OUTPUT does).
func TestAndroidIPv6TProxyVendorConnmark(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires ip6tables, iproute2 and network namespace privileges")
	}
	if os.Getenv("SING_TUN_TEST_IPTABLES_CASE") != "vendor-connmark" {
		command := exec.Command(os.Args[0], "-test.run=^TestAndroidIPv6TProxyVendorConnmark$", "-test.v")
		command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE=vendor-connmark")
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated TPROXY vendor connmark test: %v\n%s", err, output)
		}
		return
	}

	run := func(args ...string) {
		t.Helper()
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
	}

	peer := "sing-tun-test-vendor-connmark-" + strconv.Itoa(os.Getpid())
	run("ip", "netns", "add", peer)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", peer).Run()
	})
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "tun0", "type", "dummy")
	run("ip", "link", "set", "tun0", "up")
	run("ip", "link", "add", "wlan0", "type", "veth", "peer", "name", "peer0", "netns", peer)
	run("ip", "addr", "add", "2001:db8:cafe::1/64", "dev", "wlan0", "nodad")
	run("ip", "link", "set", "wlan0", "up")
	run("ip", "-n", peer, "addr", "add", "2001:db8:cafe::2/64", "dev", "peer0", "nodad")
	run("ip", "-n", peer, "link", "set", "peer0", "up")
	run("ip", "-6", "route", "add", "2001:db8:beef::/64", "via", "2001:db8:cafe::2", "dev", "wlan0")

	listenConfig := net.ListenConfig{
		Control: control.Append(func(network string, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			})
		}, control.RoutingMark(DefaultAutoRedirectOutputMark)),
	}
	listener, err := listenConfig.Listen(t.Context(), "tcp6", "[::]:0")
	if err != nil {
		t.Fatalf("listen transparent tcp6: %v", err)
	}
	defer listener.Close()
	listenPort := listener.Addr().(*net.TCPAddr).Port

	redirect := &autoRedirect{
		tunOptions: &Options{
			Name:                   "tun0",
			Inet6Address:           []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			AutoRedirectInputMark:  effectiveMark(0, DefaultAutoRedirectInputMark),
			AutoRedirectOutputMark: effectiveMark(0, DefaultAutoRedirectOutputMark),
			AutoRedirectResetMark:  effectiveMark(0x10000000, DefaultAutoRedirectResetMark),
			AutoRedirectTProxyMark: effectiveMark(0, DefaultAutoRedirectTProxyMark),
		},
		logger:             logger.NOP(),
		enableIPv6:         true,
		tableName:          "tp-mark",
		customRedirectPort: listenPort,
		interfaceFinder:    control.NewDefaultInterfaceFinder(),
	}
	localAddresses, err := redirect.findLocalAddresses()
	if err != nil {
		t.Fatal(err)
	}
	redirect.localAddresses = localAddresses
	if err = redirect.setupRedirectRoutes(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(redirect.cleanupRedirectRoutes)
	if err = redirect.setupIPTablesForFamily(&iptablesFamily{path: "ip6tables", isIPv6: true, tproxy: true}); err != nil {
		t.Fatal(err)
	}
	// Isolate TPROXY from NFQUEUE: without a running NFQUEUE listener,
	// --queue-bypass exits the mangle hook before output-tproxy runs.
	run("ip6tables", "-t", "mangle", "-D", "OUTPUT", "-j", "tp-mark-output-prematch")
	run("ip6tables", "-t", "mangle", "-D", "PREROUTING", "-j", "tp-mark-prerouting-prematch")
	// Simulate Xiaomi HyperOS tc_limiter_OUTPUT running after sing-box-output-tproxy.
	run("ip6tables", "-t", "mangle", "-A", "OUTPUT", "-o", "wlan0", "-j", "CONNMARK", "--set-xmark", "0x30000000/0x30000000")

	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			serverErr <- readErr
			return
		}
		if string(buf) != "ping" {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		_, writeErr := conn.Write([]byte("pong"))
		serverErr <- writeErr
	}()

	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp6", "[2001:db8:beef::1]:443")
	if err != nil {
		mangleOut, _ := exec.Command("ip6tables", "-t", "mangle", "-L", "-v", "-n").CombinedOutput()
		ruleOut, _ := exec.Command("ip", "-6", "rule", "show").CombinedOutput()
		routeOut, _ := exec.Command("ip", "-6", "route", "show", "table", "all").CombinedOutput()
		t.Fatalf("dial ipv6 through TPROXY with vendor connmark: %v\nrules:\n%s\nroutes:\n%s\nmangle:\n%s", err, ruleOut, routeOut, mangleOut)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	reply := make([]byte, 4)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("got reply %q, want %q", string(reply), "pong")
	}
	select {
	case err = <-serverErr:
		if err != nil {
			t.Fatalf("transparent listener error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for transparent listener")
	}
}
