//go:build linux

package tun

import (
	"net/netip"
	"testing"
)

func TestNFTablesLocalLinkAddresses(t *testing.T) {
	redirect := autoRedirect{fibAddrType: true}
	ipv4 := netip.MustParseAddr("169.254.0.1")
	ipv6 := netip.MustParseAddr("fe80::1")

	if redirect.includeNFTablesLocalAddress("eth0", ipv4) || !redirect.includeNFTablesLocalAddress("eth0", ipv6) {
		t.Fatal("with fib support, only IPv6 link-local addresses belong in the local address set")
	}
	redirect.fibAddrType = false
	if !redirect.includeNFTablesLocalAddress("eth0", ipv4) || !redirect.includeNFTablesLocalAddress("eth0", ipv6) {
		t.Fatal("without fib support, link-local addresses of both families belong in the local address set")
	}
}
