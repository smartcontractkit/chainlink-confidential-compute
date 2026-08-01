package proxyserver

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicProfileMatchesSafeURLIPv4Ranges(t *testing.T) {
	blocked := []string{
		"10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1",
		"0.0.0.1", "169.254.169.254", "192.0.0.1", "192.0.2.1",
		"198.51.100.1", "203.0.113.1", "192.88.99.1", "198.18.0.1",
		"224.0.0.1", "240.0.0.1", "255.255.255.255", "100.64.0.1",
	}
	for _, raw := range blocked {
		assert.False(t, publicProfileAllowsAddress(netip.MustParseAddr(raw)), raw)
	}
	assert.True(t, publicProfileAllowsAddress(netip.MustParseAddr("8.8.8.8")))
	assert.False(t, publicProfileAllowsAddress(netip.MustParseAddr("2001:4860:4860::8888")))
}

func lastAddrIn(prefix netip.Prefix) netip.Addr {
	octets := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		octets[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(octets)
}

func anyBlockedRangeContains(addr netip.Addr) bool {
	for _, prefix := range safeURLBlockedIPv4 {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func TestPublicProfileBlockedRangeBoundaries(t *testing.T) {
	for _, prefix := range safeURLBlockedIPv4 {
		first, last := prefix.Masked().Addr(), lastAddrIn(prefix)
		assert.False(t, publicProfileAllowsAddress(first), "first of %s", prefix)
		assert.False(t, publicProfileAllowsAddress(last), "last of %s", prefix)

		if before := first.Prev(); before.IsValid() && before.Is4() && !anyBlockedRangeContains(before) {
			assert.True(t, publicProfileAllowsAddress(before), "just below %s", prefix)
		}
		if after := last.Next(); after.IsValid() && after.Is4() && !anyBlockedRangeContains(after) {
			assert.True(t, publicProfileAllowsAddress(after), "just above %s", prefix)
		}
	}
}

var safeurlBlockedRangesAtV0_2_2 = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"0.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24",
	"198.51.100.0/24", "203.0.113.0/24", "192.88.99.0/24", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "100.64.0.0/10",
}

func TestPublicProfileMatchesSafeURLTableExactly(t *testing.T) {
	independent := make(map[netip.Prefix]struct{}, len(safeurlBlockedRangesAtV0_2_2))
	for _, raw := range safeurlBlockedRangesAtV0_2_2 {
		independent[netip.MustParsePrefix(raw)] = struct{}{}
	}
	ours := make(map[netip.Prefix]struct{}, len(safeURLBlockedIPv4))
	for _, prefix := range safeURLBlockedIPv4 {
		ours[prefix] = struct{}{}
	}

	for prefix := range independent {
		_, ok := ours[prefix]
		assert.True(t, ok, "safeurl blocks %s and we do not", prefix)
	}
	for prefix := range ours {
		_, ok := independent[prefix]
		assert.True(t, ok, "we block %s and safeurl does not", prefix)
	}

	require.Len(t, safeURLBlockedIPv4, len(safeurlBlockedRangesAtV0_2_2))
}
