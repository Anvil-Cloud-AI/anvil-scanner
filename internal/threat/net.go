//go:build darwin || linux

package threat

import (
	"net"
)

// privateRanges lists the CIDR blocks that are private, loopback, or
// link-local. isPrivateIP returns true for any address in these ranges
// as well as for the IPv6 loopback (::1) and ULA range (fc00::/7).
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 ULA (covers fc00:: – fdff::)
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, network)
		}
	}
}

// isPrivateIP returns true when addr is a private, loopback, or link-local
// address that Shodan / AbuseIPDB would refuse to look up.
func isPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
