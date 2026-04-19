package dialer

import "testing"

func TestNeedsStickyIpCachingSupportsPortUnionDomain(t *testing.T) {
	if !needsStickyIpCaching("example.com:443,8443-8450") {
		t.Fatal("expected domain port-union address to require sticky IP caching")
	}
}

func TestNeedsStickyIpCachingSkipsPortUnionIP(t *testing.T) {
	if needsStickyIpCaching("203.0.113.10:443,8443-8450") {
		t.Fatal("expected IP port-union address to skip sticky IP caching")
	}
}

func TestNeedsStickyIpCachingSkipsBracketedIPv6(t *testing.T) {
	// IPv6 IP addresses (even with port-union) should not require sticky IP caching
	if needsStickyIpCaching("[2001:db8::1]:443,8443") {
		t.Fatal("expected IPv6 IP port-union address to skip sticky IP caching")
	}
}
