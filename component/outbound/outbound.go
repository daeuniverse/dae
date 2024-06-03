/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	_ "github.com/daeuniverse/outbound/dialer/http"
	_ "github.com/daeuniverse/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/outbound/dialer/juicity"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocksr"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/dialer/trojan"
	_ "github.com/daeuniverse/outbound/dialer/tuic"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	_ "github.com/daeuniverse/outbound/protocol/hysteria2"
	_ "github.com/daeuniverse/outbound/protocol/juicity"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
	_ "github.com/daeuniverse/outbound/protocol/tuic"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
	_ "github.com/daeuniverse/outbound/transport/simpleobfs"
	_ "github.com/daeuniverse/outbound/transport/tls"
	_ "github.com/daeuniverse/outbound/transport/ws"
	_ "github.com/daeuniverse/softwind/protocol/juicity"
	_ "github.com/daeuniverse/softwind/protocol/shadowsocks"
	_ "github.com/daeuniverse/softwind/protocol/trojanc"
	_ "github.com/daeuniverse/softwind/protocol/tuic"
	_ "github.com/daeuniverse/softwind/protocol/vless"
	_ "github.com/daeuniverse/softwind/protocol/vmess"
)
