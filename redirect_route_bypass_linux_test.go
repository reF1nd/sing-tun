//go:build linux

package tun

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/sagernet/netlink"

	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

func TestBuildBypassRoutesStaticProtocol(t *testing.T) {
	for _, family := range []struct {
		name     string
		family   int
		prefixes []string
		gateway  string
		source   string
	}{
		{"ipv4", unix.AF_INET, []string{"192.0.2.1/32", "192.0.2.3/32"}, "198.51.100.1", "198.51.100.2/32"},
		{"ipv6", unix.AF_INET6, []string{"2001:db8:1::1/128", "2001:db8:1::3/128"}, "fe80::1", "2001:db8:2::2/128"},
	} {
		for _, protocol := range []netlink.RouteProtocol{unix.RTPROT_KERNEL, unix.RTPROT_RA, unix.RTPROT_STATIC} {
			t.Run(family.name+"/"+protocol.String(), func(t *testing.T) {
				var builder netipx.IPSetBuilder
				for _, prefix := range family.prefixes {
					builder.AddPrefix(netip.MustParsePrefix(prefix))
				}
				set, err := builder.IPSet()
				if err != nil {
					t.Fatal(err)
				}
				source := netlink.Route{
					LinkIndex: 7,
					Gw:        net.ParseIP(family.gateway),
					Src:       prefixToIPNet(netip.MustParsePrefix(family.source)),
					Table:     1007,
					Protocol:  protocol,
					Priority:  1024,
					Type:      unix.RTN_UNICAST,
					Scope:     netlink.SCOPE_UNIVERSE,
					MTU:       1400,
				}
				sources := []netlink.Route{source}
				routes, err := buildBypassRoutes(family.family, set, sources, 2022)
				if err != nil {
					t.Fatal(err)
				}
				if len(routes) != len(family.prefixes) {
					t.Fatalf("got %d routes, want %d", len(routes), len(family.prefixes))
				}
				for i, route := range routes {
					if route.Protocol != unix.RTPROT_STATIC || route.Table != 2022 || route.Dst.String() != family.prefixes[i] {
						t.Fatalf("unexpected policy route: %+v", route)
					}
					if route.LinkIndex != source.LinkIndex || !route.Gw.Equal(source.Gw) ||
						!routeSourceEquals(route.Src, source.Src) || route.Priority != source.Priority ||
						route.Type != source.Type || route.Scope != source.Scope || route.MTU != source.MTU {
						t.Fatalf("forwarding properties changed: %+v", route)
					}
				}
				if !reflect.DeepEqual(sources[0], source) {
					t.Fatal("modified the physical network's source route")
				}
			})
		}
	}
}

func TestReconcileBypassRoutes(t *testing.T) {
	for _, prefix := range []string{"192.0.2.0/24", "2001:db8::/64"} {
		address := netip.MustParsePrefix(prefix)
		family := unix.AF_INET
		if address.Addr().Is6() {
			family = unix.AF_INET6
		}
		base := netlink.Route{
			LinkIndex: 7,
			Dst:       prefixToIPNet(address),
			Table:     2022,
			Type:      unix.RTN_UNICAST,
			Protocol:  unix.RTPROT_STATIC,
			Priority:  1024,
			MTU:       1400,
		}
		for _, testCase := range []struct {
			name       string
			change     func(*netlink.Route)
			remove     bool
			deleteErr  error
			replaceErr error
			wantCalls  []string
			wantErr    error
		}{
			{name: "unchanged"},
			{name: "migrate RA", change: func(r *netlink.Route) { r.Protocol = unix.RTPROT_RA }, wantCalls: []string{"delete", "replace"}},
			{name: "migrate kernel", change: func(r *netlink.Route) { r.Protocol = unix.RTPROT_KERNEL }, wantCalls: []string{"delete", "replace"}},
			{name: "metric changed", change: func(r *netlink.Route) { r.Priority++ }, wantCalls: []string{"delete", "replace"}},
			{name: "interface changed", change: func(r *netlink.Route) { r.LinkIndex++ }, wantCalls: []string{"replace"}},
			{name: "MTU changed", change: func(r *netlink.Route) { r.MTU++ }, wantCalls: []string{"replace"}},
			{name: "type changed", change: func(r *netlink.Route) { r.Type = unix.RTN_UNREACHABLE }, wantCalls: []string{"replace"}},
			{name: "removed", remove: true, wantCalls: []string{"delete"}},
			{name: "delete failed", change: func(r *netlink.Route) { r.Protocol = unix.RTPROT_RA }, deleteErr: unix.EPERM, wantCalls: []string{"delete"}, wantErr: unix.EPERM},
			{name: "already deleted ESRCH", change: func(r *netlink.Route) { r.Protocol = unix.RTPROT_RA }, deleteErr: unix.ESRCH, wantCalls: []string{"delete", "replace"}},
			{name: "already deleted ENOENT", change: func(r *netlink.Route) { r.Protocol = unix.RTPROT_RA }, deleteErr: unix.ENOENT, wantCalls: []string{"delete", "replace"}},
			{name: "replace failed", change: func(r *netlink.Route) { r.Protocol = unix.RTPROT_RA }, replaceErr: unix.EPERM, wantCalls: []string{"delete", "replace"}, wantErr: unix.EPERM},
		} {
			t.Run(prefix+"/"+testCase.name, func(t *testing.T) {
				current := base
				if testCase.change != nil {
					testCase.change(&current)
				}
				desired := []netlink.Route{base}
				if testCase.remove {
					desired = nil
				}
				var calls []string
				deleteRoute := func(route *netlink.Route) error {
					calls = append(calls, "delete")
					if !reflect.DeepEqual(*route, current) {
						t.Fatalf("deletion did not preserve the old route's attributes: %+v", route)
					}
					return testCase.deleteErr
				}
				replaceRoute := func(route *netlink.Route) error {
					calls = append(calls, "replace")
					if !reflect.DeepEqual(*route, base) {
						t.Fatalf("unexpected replacement: %+v", route)
					}
					return testCase.replaceErr
				}
				changed, err := reconcileBypassRoutes(family, []netlink.Route{current}, desired, deleteRoute, replaceRoute)
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("error = %v, want %v", err, testCase.wantErr)
				}
				if !reflect.DeepEqual(calls, testCase.wantCalls) {
					t.Fatalf("calls = %v, want %v", calls, testCase.wantCalls)
				}
				if err == nil && changed != len(calls) {
					t.Fatalf("changed = %d, calls = %v", changed, calls)
				}
				if err == nil {
					calls = nil
					changed, err = reconcileBypassRoutes(family, desired, desired, deleteRoute, replaceRoute)
					if err != nil || changed != 0 || len(calls) != 0 {
						t.Fatalf("stable update wrote routes again: changed=%d, calls=%v, err=%v", changed, calls, err)
					}
				}
			})
		}
	}
}

func TestReconcileBypassDefaultRoute(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		current := netlink.Route{Table: 2022, Protocol: unix.RTPROT_STATIC}
		desired := current
		desired.Dst = defaultDestination(family)
		unexpected := func(route *netlink.Route) error {
			t.Fatalf("unchanged default route was written: %+v", route)
			return nil
		}
		changed, err := reconcileBypassRoutes(family, []netlink.Route{current}, []netlink.Route{desired}, unexpected, unexpected)
		if changed != 0 || err != nil {
			t.Fatalf("changed=%d, err=%v", changed, err)
		}
	}
}
