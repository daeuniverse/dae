package http

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type noopDialer struct{}

func (noopDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, nil
}

func TestNewHTTPProxyPreservesTLSOptionsFromOriginalURL(t *testing.T) {
	u, err := url.Parse("https://proxy.example:443?allowInsecure=1&tlsImplementation=utls&utlsImitate=chrome&sni=edge.example&alpn=h2,http/1.1")
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	dialer, err := NewHTTPProxy(u, noopDialer{})
	if err != nil {
		t.Fatalf("NewHTTPProxy returned error: %v", err)
	}

	proxy, ok := dialer.(*HttpProxy)
	if !ok {
		t.Fatalf("expected *HttpProxy, got %T", dialer)
	}

	tlsDialerValue := reflect.ValueOf(proxy.dialer).Elem()
	if got := tlsDialerValue.FieldByName("tlsImplentation").String(); got != "utls" {
		t.Fatalf("unexpected tlsImplentation: got %q want %q", got, "utls")
	}
	if got := tlsDialerValue.FieldByName("utlsImitate").String(); got != "chrome" {
		t.Fatalf("unexpected utlsImitate: got %q want %q", got, "chrome")
	}
	if !tlsDialerValue.FieldByName("skipVerify").Bool() {
		t.Fatal("expected allowInsecure to propagate to skipVerify")
	}
	if got := tlsDialerValue.FieldByName("serverName").String(); got != "edge.example" {
		t.Fatalf("unexpected serverName: got %q want %q", got, "edge.example")
	}

	nextProtos := tlsDialerValue.FieldByName("tlsConfig").Elem().FieldByName("NextProtos")
	if nextProtos.Len() != 2 || nextProtos.Index(0).String() != "h2" || nextProtos.Index(1).String() != "http/1.1" {
		t.Fatalf("unexpected NextProtos: %#v", nextProtos)
	}
}
