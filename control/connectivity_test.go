package control

import (
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
)

func TestOutboundConnectivityMapKey(t *testing.T) {
	tests := []struct {
		name     string
		outbound uint8
		network  *dialer.NetworkType
		want     uint32
	}{
		{
			name:     "tcp4",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_4,
			},
			want: 8,
		},
		{
			name:     "tcp6",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_TCP,
				IpVersion: consts.IpVersionStr_6,
			},
			want: 9,
		},
		{
			name:     "udp4",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_4,
			},
			want: 10,
		},
		{
			name:     "udp6",
			outbound: 2,
			network: &dialer.NetworkType{
				L4Proto:   consts.L4ProtoStr_UDP,
				IpVersion: consts.IpVersionStr_6,
			},
			want: 11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outboundConnectivityMapKey(tt.outbound, tt.network); got != tt.want {
				t.Fatalf("outboundConnectivityMapKey() = %d, want %d", got, tt.want)
			}
		})
	}
}
