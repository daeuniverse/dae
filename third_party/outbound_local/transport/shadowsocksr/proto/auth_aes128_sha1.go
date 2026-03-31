package proto

import (
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pool/bytes"
)

func init() {
	register("auth_aes128_sha1", NewAuthAES128SHA1)
}

func NewAuthAES128SHA1() IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_sha1",
		hmac:       common.HmacSHA1,
		hashDigest: common.SHA1Sum,
		packID:     1,
		recvInfo: recvInfo{
			recvID: 1,
			buffer: bytes.NewBuffer(nil),
		},
	}
	return a
}
