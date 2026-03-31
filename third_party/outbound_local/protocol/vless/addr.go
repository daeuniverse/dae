package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

func CompleteMetadataFromReader(m *Metadata, first4 []byte, r io.Reader) (err error) {
	m.Type = vmess.ParseMetadataType(first4[3])
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		buf := pool.Get(4)
		defer buf.Put()
		if _, err = io.ReadFull(r, buf); err != nil {
			return err
		}
		m.Hostname = net.IP(buf).String()
	case protocol.MetadataTypeIPv6:
		buf := pool.Get(16)
		defer buf.Put()
		if _, err = io.ReadFull(r, buf); err != nil {
			return err
		}
		m.Hostname = net.IP(buf).String()
	case protocol.MetadataTypeDomain:
		buf := pool.Get(1 + 255)
		defer buf.Put()
		if _, err = io.ReadFull(r, buf[:1]); err != nil {
			return err
		}
		if _, err = io.ReadFull(r, buf[1:buf[0]]); err != nil {
			return err
		}
		m.Hostname = string(buf[1 : 1+int(buf[0])])
	case protocol.MetadataTypeMsg:
		buf := pool.Get(1)
		defer buf.Put()
		if _, err = io.ReadFull(r, buf); err != nil {
			return err
		}
		m.Cmd = protocol.MetadataCmd(buf[0])
	default:
		return fmt.Errorf("CompleteMetadataFromReader: %w: invalid type: %v", vmess.ErrInvalidMetadata, first4[3])
	}
	m.Port = binary.BigEndian.Uint16(first4[1:])
	m.Network = vmess.ParseNetwork(first4[0])
	return nil
}
