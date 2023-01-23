/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package outbound

import (
	_ "github.com/v2rayA/dae/component/outbound/dialer/http"
	_ "github.com/v2rayA/dae/component/outbound/dialer/shadowsocks"
	_ "github.com/v2rayA/dae/component/outbound/dialer/shadowsocksr"
	_ "github.com/v2rayA/dae/component/outbound/dialer/socks"
	_ "github.com/v2rayA/dae/component/outbound/dialer/trojan"
	_ "github.com/v2rayA/dae/component/outbound/dialer/v2ray"
	_ "github.com/mzz2017/softwind/protocol/shadowsocks"
	_ "github.com/mzz2017/softwind/protocol/trojanc"
	_ "github.com/mzz2017/softwind/protocol/vless"
	_ "github.com/mzz2017/softwind/protocol/vmess"
)
