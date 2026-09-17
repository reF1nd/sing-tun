//go:build linux && !android

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

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
			AutoRedirectInputMark: 0x400000, AutoRedirectOutputMark: 0x200000, AutoRedirectResetMark: 0x600000,
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
		run("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "MARK", "--set-xmark", "0x200000/0xe00000")
		run("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "CONNMARK", "--save-mark", "--nfmask", "0xe00000", "--ctmask", "0xe00000")
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
