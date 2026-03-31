package anytls

import (
	"encoding/binary"

	"github.com/daeuniverse/outbound/pool"
)

const ( // cmds
	cmdWaste               = iota // Paddings
	cmdSYN                        // stream open
	cmdPSH                        // data push
	cmdFIN                        // stream close, a.k.a EOF mark
	cmdSettings                   // Settings (Client send to Server)
	cmdAlert                      // Alert
	cmdUpdatePaddingScheme        // update padding scheme
	// Since version 2
	cmdSYNACK         // Server reports to the client that the stream has been opened
	cmdHeartRequest   // Keep alive command
	cmdHeartResponse  // Keep alive command
	cmdServerSettings // Settings (Server send to client)
)

const (
	headerOverHeadSize = 1 + 4 + 2
)

// frame defines a packet from or to be multiplexed into a single connection
type frame struct {
	cmd  byte   // 1
	sid  uint32 // 4
	data []byte // 2 + len(data)
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:])
}

func writeFrame(session *session, frame frame) (int, error) {
	dataLen := len(frame.data)

	buffer := pool.Get(dataLen + headerOverHeadSize)
	defer pool.Put(buffer)

	buffer[0] = frame.cmd
	binary.BigEndian.PutUint32(buffer[1:], frame.sid)
	binary.BigEndian.PutUint16(buffer[5:], uint16(dataLen))
	copy(buffer[7:], frame.data)
	_, err := session.writeConn(buffer)
	if err != nil {
		return 0, err
	}

	return dataLen, nil
}
