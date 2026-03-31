package vmess

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/protocol"
)

func ParseMetadataType(t byte) protocol.MetadataType {
	switch t {
	case 1:
		return protocol.MetadataTypeIPv4
	case 2:
		return protocol.MetadataTypeDomain
	case 3:
		return protocol.MetadataTypeIPv6
	case 4:
		return protocol.MetadataTypeMsg
	default:
		return protocol.MetadataTypeInvalid
	}
}

func MetadataTypeToByte(typ protocol.MetadataType) byte {
	switch typ {
	case protocol.MetadataTypeIPv4:
		return 1
	case protocol.MetadataTypeDomain:
		return 2
	case protocol.MetadataTypeIPv6:
		return 3
	case protocol.MetadataTypeMsg:
		return 4
	default:
		return 0
	}
}

func ParseNetwork(n byte) string {
	switch n {
	case 1:
		return "tcp"
	case 2:
		return "udp"
	default:
		return "invalid"
	}
}

func NetworkToByte(network string) byte {
	switch network {
	case "tcp":
		return 1
	case "udp":
		return 2
	case "mux":
		return 3
	default:
		return 0
	}
}

type Metadata struct {
	protocol.Metadata

	Network       string
	authedCmdKey  [16]byte
	authedEAuthID [16]byte
}

var (
	ErrInvalidMetadata = fmt.Errorf("invalid metadata")
)

func NewServerMetadata(cmdKey, eAuthID []byte) *Metadata {
	m := Metadata{
		Metadata: protocol.Metadata{
			IsClient: false,
		},
	}
	copy(m.authedCmdKey[:], cmdKey)
	copy(m.authedEAuthID[:], eAuthID)
	return &m
}

func (m *Metadata) AddrLen() int {
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		return 4
	case protocol.MetadataTypeIPv6:
		return 16
	case protocol.MetadataTypeDomain:
		return 1 + len([]byte(m.Hostname))
	case protocol.MetadataTypeMsg:
		return 1
	default:
		return 0
	}
}

func (m *Metadata) PutAddr(dst []byte) (n int) {
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		copy(dst, net.ParseIP(m.Hostname).To4()[:4])
		return 4
	case protocol.MetadataTypeIPv6:
		copy(dst, net.ParseIP(m.Hostname)[:16])
		return 16
	case protocol.MetadataTypeDomain:
		dst[0] = byte(len([]byte(m.Hostname)))
		copy(dst[1:], m.Hostname)
		return 1 + int(dst[0])
	case protocol.MetadataTypeMsg:
		dst[0] = byte(m.Cmd)
		return 1
	default:
		return 0
	}
}

func (m *Metadata) CompleteFromInstructionData(instructionData []byte) (err error) {
	if len(instructionData) < 41 {
		return fmt.Errorf("bad req: insuffient data: expected at least 41 but got: %v", len(instructionData))
	}
	m.Type = ParseMetadataType(instructionData[40])
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		if len(instructionData) < 45 {
			return fmt.Errorf("bad ipv4 req: insuffient data: expected 45 but got: %v", len(instructionData))
		}
		m.Hostname = net.IP(instructionData[41:45]).String()
	case protocol.MetadataTypeIPv6:
		if len(instructionData) < 57 {
			return fmt.Errorf("bad ipv6 req: insuffient data: expected 57 but got: %v", len(instructionData))
		}
		m.Hostname = net.IP(instructionData[41:57]).String()
	case protocol.MetadataTypeDomain:
		if len(instructionData) < 42+int(instructionData[41]) {
			return fmt.Errorf("bad domain req: insuffient data: expected %v but got: %v", 42+int(instructionData[41]), len(instructionData))
		}
		m.Hostname = string(instructionData[42 : 42+int(instructionData[41])])
	case protocol.MetadataTypeMsg:
		if len(instructionData) < 42 {
			return fmt.Errorf("bad msg req: insuffient data: expected 42 but got: %v", len(instructionData))
		}
		m.Cmd = protocol.MetadataCmd(instructionData[41])
	default:
		return fmt.Errorf("CompleteFromInstructionData: %w: invalid type: %v", ErrInvalidMetadata, instructionData[40])
	}
	m.Port = binary.BigEndian.Uint16(instructionData[38:])
	m.Network = ParseNetwork(instructionData[37])
	cipher, err := ParseCipherFromSecurity(instructionData[35] & 0xf)
	if err != nil {
		return err
	}
	m.Cipher = string(cipher)
	return nil
}
