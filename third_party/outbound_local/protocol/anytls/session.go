package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type session struct {
	conn     netproxy.Conn
	connLock sync.Mutex

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	padding     atomic.Value
	sendPadding bool
	pktCounter  atomic.Uint32
	peerVersion byte

	seq             uint64
	sid             atomic.Uint32
	closed          atomic.Bool
	closeStreamChan chan uint32
}

func newSession(conn netproxy.Conn, seq uint64) *session {
	s := &session{
		conn:            conn,
		streams:         map[uint32]*stream{},
		seq:             seq,
		closeStreamChan: make(chan uint32, 2),
		sendPadding:     true,
	}
	s.padding.Store(DefaultPaddingFactory.Load())
	return s
}

func (s *session) newStream(addr string) (*stream, error) {
	s.sid.Add(1)
	sid := s.sid.Load()

	frame := newFrame(cmdSettings, sid)
	frame.data = settingsBytes(s.GetPadding())
	if _, err := writeFrame(s, frame); err != nil {
		return nil, err
	}

	frame = newFrame(cmdSYN, sid)
	if _, err := writeFrame(s, frame); err != nil {
		return nil, err
	}

	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	frame = newFrame(cmdPSH, sid)
	frame.data = tgtAddr
	if _, err := writeFrame(s, frame); err != nil {
		return nil, err
	}

	stream := newStream(s, sid)
	s.streamLock.Lock()
	s.streams[sid] = stream
	s.streamLock.Unlock()

	return stream, nil
}

func (s *session) newPacketStream(addr, packetAddr string) (*packetStream, error) {
	stream, err := s.newStream(addr)
	if err != nil {
		return nil, err
	}
	return &packetStream{
		stream: stream,
		addr:   packetAddr,
	}, nil
}

func (s *session) removeStream(sid uint32) {
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	if s.closed.Load() {
		return
	}
	select {
	case s.closeStreamChan <- sid:
	default:
	}
}

func (s *session) run() error {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Panic]", slog.String("stack", string(debug.Stack())))
		}
	}()
	defer func() { _ = s.Close() }()

	var header rawHeader
	for {
		if s.Closed() {
			return net.ErrClosed
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		switch header.Cmd() {
		case cmdWaste:
			if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
				return err
			}
		case cmdPSH:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				if _, err := stream.pw.Write(buf); err != nil {
					pool.Put(buf)
					return err
				}
			}
			pool.Put(buf)
		case cmdAlert:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			slog.Error("[Alert]", slog.String("msg", string(buf)))
			pool.Put(buf)
		case cmdFIN:
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				_ = stream.remoteClose()
			}
		case cmdUpdatePaddingScheme:
			if length > 0 {
				buf := pool.Get(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.Put(buf)
					return err
				}
				updatePaddingScheme(buf)
				pool.Put(buf)
			}
		case cmdSYNACK:
			if length > 0 {
				buf := pool.Get(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.Put(buf)
					return err
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					_ = stream.Close()
				}
				pool.Put(buf)
			}
		case cmdServerSettings:
			if length > 0 {
				buffer := pool.Get(length)
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					pool.Put(buffer)
					return err
				}
				// check server's version
				m := stringMapFromBytes(buffer)
				if v, err := strconv.Atoi(m["v"]); err == nil {
					s.peerVersion = byte(v)
				}
				pool.Put(buffer)
			}

		case cmdHeartRequest:
			frame := newFrame(cmdHeartResponse, sid)
			if _, err := writeFrame(s, frame); err != nil {
				return err
			}
		case cmdHeartResponse:
		default:
			return fmt.Errorf("invalid cmd: %d", header.Cmd())
		}
	}
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.streamLock.Lock()
		streams := make([]*stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.streams = make(map[uint32]*stream)
		s.streamLock.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		_ = s.conn.Close()
		return nil
	}
	return nil
}

func (s *session) Closed() bool {
	return s.closed.Load()
}

func (s *session) SetPadding(padding *paddingFactory) {
	s.padding.Store(padding)
}

func (s *session) GetPadding() *paddingFactory {
	return s.padding.Load().(*paddingFactory)
}

func (s *session) writeConn(b []byte) (n int, err error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	// calulate & send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.GetPadding()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				// logrus.Debugln(pkt, "write", l, "len", remainPayloadLen, "remain", remainPayloadLen-l)
				if remainPayloadLen > l { // this packet is all payload
					_, err = s.conn.Write(b[:l])
					if err != nil {
						return 0, err
					}
					n += l
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						padding := make([]byte, headerOverHeadSize+paddingLen)
						padding[0] = cmdWaste
						binary.BigEndian.PutUint32(padding[1:5], 0)
						binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
						b = slices.Concat(b, padding)
					}
					_, err = s.conn.Write(b)
					if err != nil {
						return 0, err
					}
					n += remainPayloadLen
					b = nil
				} else { // this packet is all padding
					padding := make([]byte, headerOverHeadSize+l)
					padding[0] = cmdWaste
					binary.BigEndian.PutUint32(padding[1:5], 0)
					binary.BigEndian.PutUint16(padding[5:7], uint16(l))
					_, err = s.conn.Write(padding)
					if err != nil {
						return 0, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			} else {
				n2, err := s.conn.Write(b)
				return n + n2, err
			}
		} else {
			s.sendPadding = false
		}
	}

	return s.conn.Write(b)
}
