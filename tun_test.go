package tun

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionsDNSAddress(t *testing.T) {
	t.Run("ipv4 no next address without ipv6 returns error instead of panic", func(t *testing.T) {
		options := Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/32")},
		}
		addrs, err := options.Inet4DNSAddress()
		require.Nil(t, addrs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "172.19.0.1/32")
	})

	t.Run("ipv4 no next address with unusable ipv6 reports ipv4 prefix", func(t *testing.T) {
		options := Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/32")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/128")},
		}
		addrs, err := options.Inet4DNSAddress()
		require.Nil(t, addrs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "172.19.0.1/32")
		require.NotContains(t, err.Error(), "fdfe:dcba:9876::1/128")
	})

	t.Run("ipv4 no next address falls back to usable ipv6", func(t *testing.T) {
		options := Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/32")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		}
		addrs, err := options.DNSServerAddress()
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("fdfe:dcba:9876::2")}, addrs)
	})

	t.Run("ipv6 no next address without ipv4 returns error", func(t *testing.T) {
		options := Options{
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/128")},
		}
		addrs, err := options.Inet6DNSAddress()
		require.Nil(t, addrs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fdfe:dcba:9876::1/128")
	})

	t.Run("explicit dns addresses filtered by family", func(t *testing.T) {
		options := Options{
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/32")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/128")},
			DNSAddress: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2606:4700:4700::1111"),
			},
		}
		inet4, err := options.Inet4DNSAddress()
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, inet4)

		inet6, err := options.Inet6DNSAddress()
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, inet6)
	})
}
