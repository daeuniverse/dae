package control

import "time"

type MsgType string

const (
	ConnectivityCheck_Done MsgType = "ConnectivityCheck_Done"
)

type Msg struct {
	Type      MsgType
	Timestamp time.Time
	Body      any
}
