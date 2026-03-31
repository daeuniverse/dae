package tls

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

func parseRange(str string) (min, max int64, err error) {
	stringArr := strings.Split(str, "-")
	if len(stringArr) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", str)
	}
	min, err = strconv.ParseInt(stringArr[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	max, err = strconv.ParseInt(stringArr[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return min, max, nil
}

type FragmentConn struct {
	rawConn     netproxy.Conn
	maxLength   int64
	minLength   int64
	maxInterval int64
	minInterval int64
}

const fragmentStackRecordScratch = 5 + 1024

func NewFragmentConn(rawConn netproxy.Conn, minLength, maxLength, minInterval, maxInterval int64) *FragmentConn {
	return &FragmentConn{
		rawConn:     rawConn,
		maxLength:   maxLength,
		minLength:   minLength,
		maxInterval: maxInterval,
		minInterval: minInterval,
	}
}

func (f *FragmentConn) Read(b []byte) (n int, err error) {
	return f.rawConn.Read(b)
}

func (f *FragmentConn) Write(b []byte) (n int, err error) {
	if len(b) <= 5 || b[0] != 22 {
		return f.rawConn.Write(b)
	}
	recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
	if len(b) < recordLen {
		return f.rawConn.Write(b)
	}
	minChunkLen, maxChunkLen := normalizeFragmentBounds(f.minLength, f.maxLength)
	data := b[5:recordLen]
	var stackScratch [fragmentStackRecordScratch]byte
	recordScratch := stackScratch[:]
	if 5+maxChunkLen > len(recordScratch) {
		recordScratch = make([]byte, 5+maxChunkLen)
	}

	if f.maxInterval == 0 {
		hello := make([]byte, 0, fragmentAggregateCap(len(data), minChunkLen))
		for from := 0; from < len(data); {
			to := common.Min(len(data), from+int(randBetween(int64(minChunkLen), int64(maxChunkLen))))
			chunkLen := to - from
			start := len(hello)
			hello = hello[:start+5+chunkLen]
			copy(hello[start:start+3], b[:3])
			hello[start+3] = byte(chunkLen >> 8)
			hello[start+4] = byte(chunkLen)
			copy(hello[start+5:start+5+chunkLen], data[from:to])
			from = to
		}
		if _, err := f.rawConn.Write(hello); err != nil {
			return 0, err
		}
	} else {
		frame := recordScratch
		for from := 0; from < len(data); {
			to := common.Min(len(data), from+int(randBetween(int64(minChunkLen), int64(maxChunkLen))))
			chunkLen := to - from
			copy(frame[:3], b[:3])
			frame[3] = byte(chunkLen >> 8)
			frame[4] = byte(chunkLen)
			copy(frame[5:5+chunkLen], data[from:to])
			if _, err := f.rawConn.Write(frame[:5+chunkLen]); err != nil {
				return 0, err
			}
			time.Sleep(time.Duration(randBetween(f.minInterval, f.maxInterval)) * time.Millisecond)
			from = to
		}
	}
	if len(b) > recordLen {
		if _, err := f.rawConn.Write(b[recordLen:]); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func normalizeFragmentBounds(minLength, maxLength int64) (minChunkLen, maxChunkLen int) {
	minChunkLen = int(minLength)
	maxChunkLen = int(maxLength)
	if minChunkLen <= 0 {
		minChunkLen = 1
	}
	if maxChunkLen < minChunkLen {
		maxChunkLen = minChunkLen
	}
	return minChunkLen, maxChunkLen
}

func fragmentAggregateCap(dataLen, minChunkLen int) int {
	chunks := dataLen / minChunkLen
	if dataLen%minChunkLen != 0 {
		chunks++
	}
	if chunks == 0 {
		chunks = 1
	}
	return dataLen + chunks*5
}

func (f *FragmentConn) Close() error {
	return f.rawConn.Close()
}

func (f *FragmentConn) SetDeadline(t time.Time) error {
	return f.rawConn.SetDeadline(t)
}

func (f *FragmentConn) SetReadDeadline(t time.Time) error {
	return f.rawConn.SetReadDeadline(t)
}

func (f *FragmentConn) SetWriteDeadline(t time.Time) error {
	return f.rawConn.SetWriteDeadline(t)
}
