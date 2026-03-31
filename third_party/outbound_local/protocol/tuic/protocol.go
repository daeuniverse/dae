package tuic

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/google/uuid"
	"github.com/olicesx/quic-go"
)

type BufferedReader interface {
	io.Reader
	io.ByteReader
}

type BufferedWriter interface {
	io.Writer
	io.ByteWriter
}

type CommandType byte

const (
	AuthenticateType = CommandType(0x00)
	ConnectType      = CommandType(0x01)
	PacketType       = CommandType(0x02)
	DissociateType   = CommandType(0x03)
	HeartbeatType    = CommandType(0x04)
)

func (c CommandType) String() string {
	switch c {
	case AuthenticateType:
		return "Authenticate"
	case ConnectType:
		return "Connect"
	case PacketType:
		return "Packet"
	case DissociateType:
		return "Dissociate"
	case HeartbeatType:
		return "Heartbeat"
	default:
		return fmt.Sprintf("UnknowCommand: %#x", byte(c))
	}
}

func (c CommandType) BytesLen() int {
	return 1
}

type CommandHead struct {
	VER  byte
	TYPE CommandType
}

func NewCommandHead(TYPE CommandType, VER byte) *CommandHead {
	return &CommandHead{
		VER:  VER,
		TYPE: TYPE,
	}
}

func ReadCommandHead(reader BufferedReader) (c *CommandHead, err error) {
	var _c CommandHead
	_c.VER, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}
	TYPE, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	_c.TYPE = CommandType(TYPE)
	return &_c, nil
}

func (c CommandHead) WriteTo(writer BufferedWriter) (err error) {
	err = writer.WriteByte(c.VER)
	if err != nil {
		return
	}
	err = writer.WriteByte(byte(c.TYPE))
	if err != nil {
		return
	}
	return
}

func (c CommandHead) WriteToBytes(buf []byte) (n int) {
	buf[0] = c.VER
	buf[1] = byte(c.TYPE)
	return 2
}

func (c CommandHead) BytesLen() int {
	return 1 + c.TYPE.BytesLen()
}

type Authenticate struct {
	*CommandHead
	UUID  uuid.UUID
	TOKEN [32]byte
	VER   byte
}

func NewAuthenticate(UUID [16]byte, TOKEN [32]byte, VER byte) *Authenticate {
	return &Authenticate{
		CommandHead: NewCommandHead(AuthenticateType, VER),
		UUID:        UUID,
		TOKEN:       TOKEN,
		VER:         VER,
	}
}

func ReadAuthenticateWithHead(head *CommandHead, reader BufferedReader) (c *Authenticate, err error) {
	var _c Authenticate
	_c.CommandHead = head
	if _c.TYPE != AuthenticateType {
		return nil, fmt.Errorf("error command type: %s", _c.TYPE)
	}
	_, err = io.ReadFull(reader, _c.UUID[:])
	if err != nil {
		return nil, fmt.Errorf("read uuid: %w", err)
	}
	_, err = io.ReadFull(reader, _c.TOKEN[:])
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	return &_c, nil
}

func ReadAuthenticate(reader BufferedReader) (c *Authenticate, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadAuthenticateWithHead(head, reader)
}

func GenToken(state quic.ConnectionState, uuid [16]byte, password string) (token [32]byte, err error) {
	var tokenBytes []byte
	tokenBytes, err = state.TLS.ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)
	if err != nil {
		return
	}
	copy(token[:], tokenBytes)
	return
}

func (c Authenticate) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	_, err = writer.Write(c.UUID[:])
	if err != nil {
		return
	}
	_, err = writer.Write(c.TOKEN[:])
	if err != nil {
		return
	}
	return
}

func (c Authenticate) BytesLen() int {
	return c.CommandHead.BytesLen() + 16 + 32
}

type Connect struct {
	*CommandHead
	ADDR *Address
}

func NewConnect(ADDR *Address, VER byte) *Connect {
	return &Connect{
		CommandHead: NewCommandHead(ConnectType, VER),
		ADDR:        ADDR,
	}
}

func ReadConnectWithHead(head *CommandHead, reader BufferedReader) (c *Connect, err error) {
	var _c Connect
	_c.CommandHead = head
	if _c.TYPE != ConnectType {
		err = fmt.Errorf("error command type: %s", _c.TYPE)
		return nil, err
	}
	_c.ADDR, err = ReadAddress(reader)
	if err != nil {
		return nil, err
	}
	return &_c, nil
}

func ReadConnect(reader BufferedReader) (c *Connect, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadConnectWithHead(head, reader)
}

func (c Connect) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = c.ADDR.WriteTo(writer)
	if err != nil {
		return
	}
	return
}

func (c Connect) WriteToBytes(b []byte) (n int) {
	n += c.CommandHead.WriteToBytes(b)
	n += c.ADDR.WriteToBytes(b[2:])
	return n
}

func (c Connect) BytesLen() int {
	return c.CommandHead.BytesLen() + c.ADDR.BytesLen()
}

type Packet struct {
	*CommandHead
	ASSOC_ID   uint16
	PKT_ID     uint16
	FRAG_TOTAL uint8
	FRAG_ID    uint8
	SIZE       uint16
	ADDR       *Address
	DATA       []byte
}

func NewPacket(ASSOC_ID uint16, PKT_ID uint16, FRGA_TOTAL uint8, FRAG_ID uint8, SIZE uint16, ADDR *Address, DATA []byte, VER byte) *Packet {
	return &Packet{
		CommandHead: NewCommandHead(PacketType, VER),
		ASSOC_ID:    ASSOC_ID,
		PKT_ID:      PKT_ID,
		FRAG_ID:     FRAG_ID,
		FRAG_TOTAL:  FRGA_TOTAL,
		SIZE:        SIZE,
		ADDR:        ADDR,
		DATA:        DATA,
	}
}

func ReadPacketWithHead(head *CommandHead, reader BufferedReader) (c *Packet, err error) {
	var _c Packet
	_c.CommandHead = head
	if _c.TYPE != PacketType {
		err = fmt.Errorf("error command type: %s", _c.TYPE)
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.ASSOC_ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.PKT_ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.FRAG_TOTAL)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.FRAG_ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.SIZE)
	if err != nil {
		return nil, err
	}
	_c.ADDR, err = ReadAddress(reader)
	if err != nil {
		return nil, err
	}
	_c.DATA = make([]byte, _c.SIZE)
	_, err = io.ReadFull(reader, _c.DATA)
	if err != nil {
		return nil, err
	}
	return &_c, nil
}

func ReadPacket(reader BufferedReader) (c *Packet, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadPacketWithHead(head, reader)
}

func (c Packet) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.ASSOC_ID)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.PKT_ID)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.FRAG_TOTAL)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.FRAG_ID)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.SIZE)
	if err != nil {
		return
	}
	err = c.ADDR.WriteTo(writer)
	if err != nil {
		return
	}
	_, err = writer.Write(c.DATA)
	if err != nil {
		return
	}
	return
}

func (c Packet) BytesLen() int {
	return c.CommandHead.BytesLen() + 4 + 2 + c.ADDR.BytesLen() + len(c.DATA)
}

var PacketOverHead = NewPacket(0, 0, 0, 0, 0, NewAddressAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 0)), nil, 0).BytesLen()

type Dissociate struct {
	*CommandHead
	ASSOC_ID uint16
}

func NewDissociate(ASSOC_ID uint16, VER byte) *Dissociate {
	return &Dissociate{
		CommandHead: NewCommandHead(DissociateType, VER),
		ASSOC_ID:    ASSOC_ID,
	}
}

func ReadDissociateWithHead(head *CommandHead, reader BufferedReader) (c *Dissociate, err error) {
	var _c Dissociate
	_c.CommandHead = head
	if _c.TYPE != DissociateType {
		err = fmt.Errorf("error command type: %s", _c.TYPE)
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.ASSOC_ID)
	if err != nil {
		return nil, err
	}
	return &_c, nil
}

func ReadDissociate(reader BufferedReader) (c *Dissociate, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadDissociateWithHead(head, reader)
}

func (c Dissociate) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.ASSOC_ID)
	if err != nil {
		return
	}
	return
}

func (c Dissociate) BytesLen() int {
	return c.CommandHead.BytesLen() + 4
}

type Heartbeat struct {
	*CommandHead
}

func NewHeartbeat(VER byte) *Heartbeat {
	return &Heartbeat{
		CommandHead: NewCommandHead(HeartbeatType, VER),
	}
}

func ReadHeartbeatWithHead(head *CommandHead, reader BufferedReader) (c *Heartbeat, err error) {
	var _c Heartbeat
	_c.CommandHead = head
	if _c.TYPE != HeartbeatType {
		err = fmt.Errorf("error command type: %s", _c.TYPE)
		return nil, err
	}
	return &_c, nil
}

func ReadHeartbeat(reader BufferedReader) (c *Heartbeat, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadHeartbeatWithHead(head, reader)
}

// Addr types
const (
	AtypDomainName byte = 0
	AtypIPv4       byte = 1
	AtypIPv6       byte = 2
	AtypNone       byte = 255 // Address type None is used in Packet commands that is not the first fragment of a UDP packet.
)

type Address struct {
	TYPE byte
	ADDR []byte
	PORT uint16
}

func NewAddress(metadata *protocol.Metadata) *Address {
	var addrType byte
	var addr []byte
	switch metadata.Type {
	case protocol.MetadataTypeIPv4:
		addrType = AtypIPv4
		addr = net.ParseIP(metadata.Hostname).To4()
	case protocol.MetadataTypeIPv6:
		addrType = AtypIPv6
		addr = net.ParseIP(metadata.Hostname).To16()
	case protocol.MetadataTypeDomain:
		addrType = AtypDomainName
		addr = make([]byte, len(metadata.Hostname)+1)
		addr[0] = byte(len(metadata.Hostname))
		copy(addr[1:], metadata.Hostname)
	}

	return &Address{
		TYPE: addrType,
		ADDR: addr,
		PORT: metadata.Port,
	}
}

func NewAddressNetAddr(addr net.Addr) (*Address, error) {
	if addr, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		if addrPort := addr.AddrPort(); addrPort.IsValid() { // sing's M.Socksaddr maybe return an invalid AddrPort if it's a DomainName
			return NewAddressAddrPort(addrPort), nil
		}
	}
	addrStr := addr.String()
	if addrPort, err := netip.ParseAddrPort(addrStr); err == nil {
		return NewAddressAddrPort(addrPort), nil
	}
	metadata, err := protocol.ParseMetadata(addrStr)
	if err != nil {
		return &Address{}, err
	}
	return NewAddress(&metadata), nil
}

func NewAddressAddrPort(addrPort netip.AddrPort) *Address {
	var addrType byte
	port := addrPort.Port()
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		addrType = AtypIPv4
	} else {
		addrType = AtypIPv6
	}
	return &Address{
		TYPE: addrType,
		ADDR: addr.AsSlice(),
		PORT: port,
	}
}

func ReadAddress(reader BufferedReader) (c *Address, err error) {
	var _c Address
	_c.TYPE, err = reader.ReadByte()
	if err != nil {
		return
	}
	switch _c.TYPE {
	case AtypIPv4:
		_c.ADDR = make([]byte, net.IPv4len)
		_, err = io.ReadFull(reader, _c.ADDR)
		if err != nil {
			return
		}
	case AtypIPv6:
		_c.ADDR = make([]byte, net.IPv6len)
		_, err = io.ReadFull(reader, _c.ADDR)
		if err != nil {
			return
		}
	case AtypDomainName:
		var addrLen byte
		addrLen, err = reader.ReadByte()
		if err != nil {
			return
		}
		_c.ADDR = make([]byte, addrLen+1)
		_c.ADDR[0] = addrLen
		_, err = io.ReadFull(reader, _c.ADDR[1:])
		if err != nil {
			return
		}
	}

	if _c.TYPE == AtypNone {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &_c.PORT)
	if err != nil {
		return
	}
	return &_c, nil
}

func (c Address) WriteTo(writer BufferedWriter) (err error) {
	err = writer.WriteByte(c.TYPE)
	if err != nil {
		return
	}
	if c.TYPE == AtypNone {
		return
	}
	_, err = writer.Write(c.ADDR[:])
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.PORT)
	if err != nil {
		return
	}
	return
}

func (c Address) WriteToBytes(b []byte) (n int) {
	b[0] = c.TYPE
	if c.TYPE == AtypNone {
		return
	}
	n = copy(b[1:], c.ADDR)
	binary.BigEndian.PutUint16(b[1+n:], c.PORT)
	return 3 + n
}

func (c Address) String() string {
	switch c.TYPE {
	case AtypDomainName:
		return net.JoinHostPort(string(c.ADDR[1:]), strconv.Itoa(int(c.PORT)))
	default:
		addr, _ := netip.AddrFromSlice(c.ADDR)
		addrPort := netip.AddrPortFrom(addr, c.PORT)
		return addrPort.String()
	}
}

func (c Address) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   c.ADDR,
		Port: int(c.PORT),
		Zone: "",
	}
}

func (c Address) BytesLen() int {
	return 1 + len(c.ADDR) + 2
}

const (
	ProtocolError         = quic.ApplicationErrorCode(0xfffffff0)
	AuthenticationFailed  = quic.ApplicationErrorCode(0xfffffff1)
	AuthenticationTimeout = quic.ApplicationErrorCode(0xfffffff2)
	BadCommand            = quic.ApplicationErrorCode(0xfffffff3)
)
