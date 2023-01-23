/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, mzz2017 (mzz@tuta.io). All rights reserved.
 */

package outbound

import (
	_ "foo/component/outbound/dialer/http"
	_ "foo/component/outbound/dialer/shadowsocks"
	_ "foo/component/outbound/dialer/shadowsocksr"
	_ "foo/component/outbound/dialer/socks"
	_ "foo/component/outbound/dialer/trojan"
	_ "foo/component/outbound/dialer/v2ray"
	_ "github.com/mzz2017/softwind/protocol/shadowsocks"
	_ "github.com/mzz2017/softwind/protocol/trojanc"
	_ "github.com/mzz2017/softwind/protocol/vless"
	_ "github.com/mzz2017/softwind/protocol/vmess"
)
