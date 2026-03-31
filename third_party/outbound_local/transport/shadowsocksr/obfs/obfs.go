package obfs

import (
	"strings"
)

type Creator func() IObfs

type constructor struct {
	New      Creator
	Overhead int
}

var (
	creatorMap = make(map[string]*constructor)
)

type IObfs interface {
	SetServerInfo(s *ServerInfo)
	GetServerInfo() (s *ServerInfo)
	Encode(data []byte) (encodedData []byte, err error)
	Decode(data []byte) (decodedData []byte, needSendBack bool, err error)
	SetData(data interface{})
	GetData() interface{}
}

func register(name string, c *constructor) {
	creatorMap[name] = c
}

// NewObfs create an Obfs object by name and return as an IObfs interface
func NewObfs(name string) *constructor {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c
	}
	return nil
}

type ServerInfo struct {
	Host  string
	Port  uint16
	Param string

	AddrLen int
	Key     []byte
	IVLen   int
}
