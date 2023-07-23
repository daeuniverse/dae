/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	_ "github.com/daeuniverse/dae/component/outbound/dialer/http"
	_ "github.com/daeuniverse/dae/component/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/dae/component/outbound/dialer/shadowsocksr"
	_ "github.com/daeuniverse/dae/component/outbound/dialer/socks"
	_ "github.com/daeuniverse/dae/component/outbound/dialer/trojan"
	_ "github.com/daeuniverse/dae/component/outbound/dialer/tuic"
	_ "github.com/daeuniverse/dae/component/outbound/dialer/v2ray"
	_ "github.com/daeuniverse/dae/component/outbound/transport/simpleobfs"
	_ "github.com/daeuniverse/dae/component/outbound/transport/tls"
	_ "github.com/daeuniverse/dae/component/outbound/transport/ws"
	_ "github.com/mzz2017/softwind/protocol/shadowsocks"
	_ "github.com/mzz2017/softwind/protocol/trojanc"
	_ "github.com/mzz2017/softwind/protocol/tuic"
	_ "github.com/mzz2017/softwind/protocol/vless"
	_ "github.com/mzz2017/softwind/protocol/vmess"
)
