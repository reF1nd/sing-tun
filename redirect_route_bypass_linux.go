//go:build linux

package tun

import (
	"errors"
	"net"
	"net/netip"
	"slices"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

// Kept separate from Android service setup so route generation and migration
// can be tested without a VpnService or privileged netlink access.
func reconcileBypassRoutes(family int, current, desired []netlink.Route, deleteRoute, replaceRoute func(*netlink.Route) error) (int, error) {
	desiredByDestination := make(map[string]*netlink.Route, len(desired))
	for index := range desired {
		desiredByDestination[desired[index].Dst.String()] = &desired[index]
	}
	matched := make(map[string]bool, len(desired))
	var changed int
	for index := range current {
		currentRoute := &current[index]
		if currentRoute.Dst == nil {
			currentRoute.Dst = defaultDestination(family)
		}
		destination := currentRoute.Dst.String()
		desiredRoute, exists := desiredByDestination[destination]
		if exists && bypassRouteEquals(currentRoute, desiredRoute) {
			matched[destination] = true
			continue
		}
		// RouteReplace only overwrites a route with the same metric; a
		// current route with another metric would survive alongside it.
		// Delete a legacy kernel/RA route before replacing its protocol, so
		// Android's route observers receive RTM_DELROUTE for the old route.
		// They ignore RTM_NEWROUTE for our static replacement.
		if !exists || currentRoute.Priority != desiredRoute.Priority || currentRoute.Protocol != desiredRoute.Protocol {
			err := deleteRoute(currentRoute)
			if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				return changed, E.Cause(err, "delete bypass route ", currentRoute.Dst)
			}
			changed++
		}
	}
	for index := range desired {
		desiredRoute := &desired[index]
		if matched[desiredRoute.Dst.String()] {
			continue
		}
		err := replaceRoute(desiredRoute)
		if err != nil {
			return changed, E.Cause(err, "add bypass route ", desiredRoute.Dst)
		}
		changed++
	}
	return changed, nil
}

func bypassRouteEquals(left *netlink.Route, right *netlink.Route) bool {
	return left.Protocol == right.Protocol &&
		left.Type == right.Type &&
		left.MTU == right.MTU &&
		left.LinkIndex == right.LinkIndex &&
		left.Scope == right.Scope &&
		left.Priority == right.Priority &&
		left.Gw.Equal(right.Gw) &&
		routeSourceEquals(left.Src, right.Src)
}

func routeSourceEquals(left *net.IPNet, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.IP.Equal(right.IP) && slices.Equal(left.Mask, right.Mask)
}

func buildBypassRoutes(family int, set *netipx.IPSet, sources []netlink.Route, tableIndex int) ([]netlink.Route, error) {
	remaining := set
	var routes []netlink.Route
	for _, source := range sources {
		if len(remaining.Ranges()) == 0 {
			break
		}
		destination := routeDestination(family, source.Dst)
		if !destination.IsValid() {
			continue
		}
		part, err := intersectPrefix(remaining, destination)
		if err != nil {
			return nil, err
		}
		if len(part.Ranges()) == 0 {
			continue
		}
		for _, prefix := range part.Prefixes() {
			route := source
			route.Dst = prefixToIPNet(prefix)
			route.Table = tableIndex
			// This is a userspace policy route, not a kernel/RA-discovered
			// route. Android's IpClient observes the latter by interface,
			// regardless of table, and would import every bypass prefix into
			// the physical network's LinkProperties.
			route.Protocol = unix.RTPROT_STATIC
			routes = append(routes, route)
		}
		var remainingBuilder netipx.IPSetBuilder
		remainingBuilder.AddSet(remaining)
		remainingBuilder.RemoveSet(part)
		remaining, err = remainingBuilder.IPSet()
		if err != nil {
			return nil, err
		}
	}
	return routes, nil
}

func unspecifiedPrefix(family int) netip.Prefix {
	if family == unix.AF_INET {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

func intersectPrefix(set *netipx.IPSet, prefix netip.Prefix) (*netipx.IPSet, error) {
	var prefixBuilder netipx.IPSetBuilder
	prefixBuilder.AddPrefix(prefix)
	prefixSet, err := prefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	var builder netipx.IPSetBuilder
	builder.AddSet(set)
	builder.Intersect(prefixSet)
	return builder.IPSet()
}

func routeDestination(family int, destination *net.IPNet) netip.Prefix {
	if destination == nil {
		return unspecifiedPrefix(family)
	}
	prefix, valid := netipx.FromStdIPNet(destination)
	if !valid {
		return netip.Prefix{}
	}
	return prefix
}
