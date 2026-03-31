package obfs

func init() {
	register("plain", &constructor{
		New:      newPlainObfs,
		Overhead: 0,
	})
}

type plain struct {
	ServerInfo
}

func newPlainObfs() IObfs {
	p := &plain{}
	return p
}

func (p *plain) SetServerInfo(s *ServerInfo) {
	p.ServerInfo = *s
}

func (p *plain) GetServerInfo() (s *ServerInfo) {
	return &p.ServerInfo
}

func (p *plain) Encode(data []byte) (encodedData []byte, err error) {
	return data, nil
}

func (p *plain) Decode(data []byte) (decodedData []byte, needSendBack bool, err error) {
	return data, false, nil
}

func (p *plain) SetData(data interface{}) {

}

func (p *plain) GetData() interface{} {
	return nil
}
