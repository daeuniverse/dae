package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
)

const CheckMark = -1

var (
	defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)
	settingsBytes = func(padding *paddingFactory) []byte {
		return fmt.Appendf(nil, "v=2\nclient=dae\npadding-md5=%s", padding.Md5)
	}
)

var DefaultPaddingFactory atomic.Value

type paddingFactory struct {
	scheme    map[string]string
	RawScheme []byte
	Stop      uint32
	Md5       string
}

func init() {
	updatePaddingScheme(defaultPaddingScheme)
}

func updatePaddingScheme(rawScheme []byte) bool {
	if p := NewPaddingFactory(rawScheme); p != nil {
		DefaultPaddingFactory.Store(p)
		return true
	}
	return false
}

func stringMapFromBytes(b []byte) map[string]string {
	m := make(map[string]string)
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		v := strings.SplitN(line, "=", 2)
		if len(v) == 2 {
			m[v[0]] = v[1]
		}
	}
	return m
}

func NewPaddingFactory(rawScheme []byte) *paddingFactory {
	p := &paddingFactory{
		RawScheme: rawScheme,
		Md5:       fmt.Sprintf("%x", md5.Sum(rawScheme)),
	}
	scheme := stringMapFromBytes(rawScheme)
	if len(scheme) == 0 {
		return nil
	}
	if stop, err := strconv.Atoi(scheme["stop"]); err == nil {
		p.Stop = uint32(stop)
	} else {
		return nil
	}
	p.scheme = scheme
	return p
}

func (p *paddingFactory) GenerateRecordPayloadSizes(pkt uint32) (pktSizes []int) {
	if s, ok := p.scheme[strconv.Itoa(int(pkt))]; ok {
		sRanges := strings.Split(s, ",")
		for _, sRange := range sRanges {
			sRangeMinMax := strings.Split(sRange, "-")
			if len(sRangeMinMax) == 2 {
				_min, err := strconv.ParseInt(sRangeMinMax[0], 10, 64)
				if err != nil {
					continue
				}
				_max, err := strconv.ParseInt(sRangeMinMax[1], 10, 64)
				if err != nil {
					continue
				}
				_min, _max = min(_min, _max), max(_min, _max)
				if _min <= 0 || _max <= 0 {
					continue
				}
				if _min == _max {
					pktSizes = append(pktSizes, int(_min))
				} else {
					i, _ := rand.Int(rand.Reader, big.NewInt(_max-_min))
					pktSizes = append(pktSizes, int(i.Int64()+_min))
				}
			} else if sRange == "c" {
				pktSizes = append(pktSizes, CheckMark)
			}
		}
	}
	return
}
