package proto

import (
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
)

func init() {
	register("origin", NewOrigin)
}

type origin struct {
	ServerInfo
}

func NewOrigin() IProtocol {
	a := &origin{}
	return a
}

func (o *origin) InitWithServerInfo(s *ServerInfo) {
	o.ServerInfo = *s
}

func (o *origin) GetServerInfo() (s *ServerInfo) {
	return &o.ServerInfo
}

func (a *origin) EncodePkt(buf *bytes.Buffer) (err error) {
	return nil
}

func (a *origin) DecodePkt(in []byte) (out pool.Bytes, err error) {
	return pool.B(in), nil
}

func (o *origin) Encode(data []byte) (encryptedData []byte, err error) {
	return data, nil
}

func (o *origin) Decode(data []byte) ([]byte, int, error) {
	return data, len(data), nil
}

func (o *origin) SetData(data interface{}) {

}

func (o *origin) GetData() interface{} {
	return nil
}

func (o *origin) GetOverhead() int {
	return 0
}
