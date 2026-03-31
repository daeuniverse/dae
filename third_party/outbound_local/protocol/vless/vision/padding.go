package vision

import (
	"bytes"
	"encoding/binary"

	"github.com/daeuniverse/outbound/pool"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/google/uuid"
)

const (
	PaddingHeaderLen = len(uuid.Nil) + 1 + 2 + 2 // =21

	commandPaddingContinue byte = 0x00
	commandPaddingEnd      byte = 0x01
	commandPaddingDirect   byte = 0x02

	BufferSize = 32 * 1024
)

func ApplyPaddingFromPool(p []byte, command byte, userUUID []byte, longPadding bool) (prefix, suffix pool.PB) {
	contentLen := int32(len(p))
	var paddingLen int32
	if contentLen < 900 && longPadding {
		//logrus.Debugln("long padding")
		paddingLen = fastrand.Int31n(500) + 900 - contentLen
	} else {
		paddingLen = fastrand.Int31n(256)
	}

	prefix = pool.Get(len(userUUID) + 1 + 2 + 2)
	suffix = pool.Get(int(paddingLen))
	start := 0
	if userUUID != nil {
		copy(prefix, userUUID[:])
		start += len(userUUID)
	}
	prefix[start] = command
	start++
	binary.BigEndian.PutUint16(prefix[start:], uint16(contentLen))
	start += 2
	binary.BigEndian.PutUint16(prefix[start:], uint16(paddingLen))
	// logrus.Debugln("XTLS Vision write padding2: command=%d, payloadLen=%d, paddingLen=%d", command, contentLen, paddingLen)
	return prefix, suffix
}

func ReshapeBytes(b []byte) (_ []byte, b2 []byte) {
	if len(b) < BufferSize-PaddingHeaderLen {
		return b, nil
	}
	index := bytes.LastIndex(b, tlsApplicationDataStart)
	if index < PaddingHeaderLen || index > BufferSize-PaddingHeaderLen {
		index = BufferSize / 2
	}
	b2 = b[index:]
	b = b[:index]
	return b, b2
}
