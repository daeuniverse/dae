package obfs

import (
	rand "github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/transport/shadowsocksr/internal/crypto"
)

type randomHead struct {
	ServerInfo
	rawTransSent     bool
	rawTransReceived bool
	hasSentHeader    bool
	dataBuffer       []byte
}

func init() {
	register("random_head", &constructor{
		New:      newRandomHead,
		Overhead: 0,
	})
}

func newRandomHead() IObfs {
	p := &randomHead{}
	return p
}

func (r *randomHead) SetServerInfo(s *ServerInfo) {
	r.ServerInfo = *s
}

func (r *randomHead) GetServerInfo() (s *ServerInfo) {
	return &r.ServerInfo
}

func (r *randomHead) SetData(data interface{}) {

}

func (r *randomHead) GetData() interface{} {
	return nil
}

func (r *randomHead) Encode(data []byte) (encodedData []byte, err error) {
	if r.rawTransSent {
		return data, nil
	}

	dataLength := len(data)
	if r.hasSentHeader {
		if dataLength > 0 {
			d := make([]byte, len(r.dataBuffer)+dataLength)
			copy(d, r.dataBuffer)
			copy(d[len(r.dataBuffer):], data)
			r.dataBuffer = d
		} else {
			encodedData = r.dataBuffer
			r.dataBuffer = nil
			r.rawTransSent = true
		}
	} else {
		size := rand.Intn(96) + 8
		encodedData = make([]byte, size)
		_, _ = rand.Read(encodedData)
		crypto.SetCRC32(encodedData, size)

		d := make([]byte, dataLength)
		copy(d, data)
		r.dataBuffer = d
	}
	r.hasSentHeader = true
	return
}

func (r *randomHead) Decode(data []byte) (decodedData []byte, needSendBack bool, err error) {
	if r.rawTransReceived {
		return data, false, nil
	}
	r.rawTransReceived = true
	return data, true, nil
}
