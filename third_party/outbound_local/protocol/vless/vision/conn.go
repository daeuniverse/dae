package vision

import (
	"bytes"
	"crypto/subtle"
	gotls "crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
)

var (
	_ io.Writer = (*writeWrapper)(nil)
	_ io.Reader = (*readWrapper)(nil)
	// _ io.ReaderFrom = (*Conn)(nil)
	_ io.WriterTo = (*Conn)(nil)
)

type readWrapper struct {
	directRead bool
	vision     *Conn
}

func (r *readWrapper) Read(p []byte) (n int, err error) {
	if r.directRead {
		// logrus.Println("direct read")
		return r.vision.Conn.Read(p)
	}
	return r.vision.overlayConn.Read(p)
}

type writeWrapper struct {
	writeDirect bool
	vision      *Conn
}

func (w *writeWrapper) Write(p []byte) (int, error) {
	// logrus.Println("write wrapper", "w.writeDirect", w.writeDirect)
	if w.writeDirect {
		return w.vision.Conn.Write(p)
	}
	return w.vision.overlayConn.Write(p)
}

type Conn struct {
	net.Conn                  // underlay conn (net.Conn/net.PacketConn)
	overlayConn netproxy.Conn // (vless.Conn)
	userUUID    []byte

	tlsConn  netproxy.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer

	needHandshake              bool
	packetsToFilter            int
	isTLS                      bool
	isTLS12orAbove             bool
	enableXTLS                 bool
	cipher                     uint16
	remainingServerHello       uint16
	readRemainingContent       int
	readRemainingPadding       int
	readFilterUUID             bool
	readLastCommand            byte
	writeFilterApplicationData bool
	writer                     *writeWrapper
	reader                     *readWrapper
	toWriteDirect              bool
	toReadDirect               bool

	muWrite sync.Mutex
	muRead  sync.Mutex
}

func (vc *Conn) Read(b []byte) (int, error) {
	vc.muRead.Lock()
	defer vc.muRead.Unlock()
	if vc.toReadDirect {
		return vc.reader.Read(b)
	}
	return vc.read(b)
}

func isTCPConnUnixConn(conn any) bool {
	if _, ok := conn.(*net.TCPConn); ok {
		return true
	} else if _, ok := conn.(*net.UnixConn); ok {
		return true
	}
	return false
}

// getUnderlayTCPConnUnixConn gets the underlay TCPConn and UnixConn.
// Use it carefully!
func getUnderlayTCPConnUnixConn(conn any) (any, bool) {
	// log.Printf("Type: %T", conn)
	val := reflect.ValueOf(conn)
	for {
		if !val.IsValid() {
			return conn, false
		}
		if val.CanInterface() && isTCPConnUnixConn(val.Interface()) {
			// log.Printf("Type: %T", val.Interface())
			return val.Interface(), true
		}
		switch val.Kind() {
		case reflect.Interface, reflect.Pointer:
			if val.IsNil() {
				return conn, false
			}
			val = val.Elem()
		case reflect.Struct:
			field := val.FieldByName("Conn")
			if !field.IsValid() {
				return conn, false
			}
			val = field
		default:
			return conn, false
		}
	}
}

// WriteTo implements io.WriterTo.
func (vc *Conn) WriteTo(w io.Writer) (n int64, err error) {
	if !vc.reader.directRead {
		b := pool.Get(4096)
		for {
			_n, err := vc.Read(b)
			if err != nil {
				b.Put()
				return n, err
			}
			if _, err = w.Write(b[:_n]); err != nil {
				b.Put()
				return n, err
			}
			n += int64(_n)
			if vc.reader.directRead {
				b.Put()
				break
			}
		}
	}
	// It is safe to get the TCPConn here, because directRead == true.
	conn, _ := getUnderlayTCPConnUnixConn(vc.Conn)
	// w is *sniffing.ConnSniffer.
	// It is safe to get the TCPConn here, because we are downloading something and sniffing is over.
	w_, _ := getUnderlayTCPConnUnixConn(w)
	_n, err := conn.(io.WriterTo).WriteTo(w_.(io.Writer))
	// log.Println("Read", n, _n)
	n += _n
	return n, err
}

func (vc *Conn) read(b []byte) (int, error) {
	if vc.readRemainingContent > 0 {
		if vc.readRemainingContent < len(b) {
			b = b[:vc.readRemainingContent]
		}
		n, err := vc.reader.Read(b)
		vc.readRemainingContent -= n
		vc.FilterTLS(b[:n])
		// logrus.Println("isTLS4", vc.isTLS, vc.readRemainingContent, n)
		return n, err
	}
	if vc.readRemainingPadding > 0 {
		_, err := io.CopyN(io.Discard, vc.reader, int64(vc.readRemainingPadding))
		if err != nil {
			return 0, err
		}
		vc.readRemainingPadding = 0
	}
	n := 0
	if !vc.toReadDirect {
		switch vc.readLastCommand {
		case commandPaddingContinue:
			headerUUIDLen := 0
			if vc.readFilterUUID {
				headerUUIDLen = len(uuid.Nil)
			}
			var header []byte
			if need := headerUUIDLen + PaddingHeaderLen - len(uuid.Nil); len(b) < need {
				header = make([]byte, need)
			} else {
				header = b[:need]
			}
			// logrus.Println("read 1")
			_, err := io.ReadFull(vc.reader, header)
			if err != nil {
				return 0, err
			}
			// logrus.Println("read 2")
			if vc.readFilterUUID {
				vc.readFilterUUID = false
				if subtle.ConstantTimeCompare(vc.userUUID[:], header[:len(uuid.Nil)]) != 1 {
					id, e := uuid.FromBytes(header[:len(uuid.Nil)])
					err = fmt.Errorf("XTLS Vision server responded unknown UUID: %s: %w",
						id.String(), e)
					// logrus.Errorln(err.Error())
					return 0, err
				}
				header = header[len(uuid.Nil):]
			}
			vc.readRemainingPadding = int(binary.BigEndian.Uint16(header[3:]))
			vc.readRemainingContent = int(binary.BigEndian.Uint16(header[1:]))
			vc.readLastCommand = header[0]
			// logrus.Infof("XTLS Vision read padding: command=%d, payloadLen=%d, paddingLen=%d",
			// vc.readLastCommand, vc.readRemainingContent, vc.readRemainingPadding)
			return vc.read(b)
		case commandPaddingEnd:
			vc.toReadDirect = true
			return vc.read(b)
		case commandPaddingDirect:
			// logrus.Infoln("commandPaddingDirect")
			needReturn := false
			if vc.input != nil {
				// logrus.Infoln("commandPaddingDirect: 1", vc.input.Len())
				if vc.input.Len() > 0 {
					_n, err := vc.input.Read(b)
					if err != nil {
						return 0, err
					}
					n += _n
				}
				// logrus.Infoln("commandPaddingDirect: 1?", vc.input.Len())
				if vc.input.Len() == 0 {
					needReturn = true
					vc.input = nil
				} else { // buffer is full
					// logrus.Infoln("commandPaddingDirect: 1? full")
					return len(b), nil
				}
			}
			if vc.rawInput != nil {
				// logrus.Infoln("commandPaddingDirect: 2")
				if vc.rawInput.Len() > 0 {
					_n, err := vc.rawInput.Read(b[n:])
					if err != nil {
						return n + _n, err
					}
					n += _n
				}
				needReturn = true
				// logrus.Infoln("commandPaddingDirect: 2?", vc.rawInput.Len())
				if vc.rawInput.Len() == 0 {
					vc.rawInput = nil
				}
			}
			if vc.input == nil && vc.rawInput == nil {
				vc.toReadDirect = true
				vc.reader.directRead = true
				// logrus.Infoln("XTLS Vision direct read start")
			}
			if needReturn {
				return n, nil
			}
		default:
			err := fmt.Errorf("XTLS Vision read unknown command: %d", vc.readLastCommand)
			// log.Debugln(err.Error())
			return 0, err
		}
	}
	return vc.reader.Read(b[n:])
}

func (vc *Conn) Write(p []byte) (int, error) {
	vc.muWrite.Lock()
	defer vc.muWrite.Unlock()
	// logrus.Println("VISION CONN WRITE", hex.EncodeToString(p), "vc.writeFilterApplicationData", vc.writeFilterApplicationData)
	if vc.writeFilterApplicationData {
		err := vc.write(p)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return vc.writer.Write(p)
}

// // ReadFrom implements io.ReaderFrom.
// func (vc *Conn) ReadFrom(r io.Reader) (n int64, err error) {
// 	if !vc.writer.writeDirect {
// 		b := pool.Get(4096)
// 		for {
// 			_n, err := r.Read(b)
// 			if err != nil {
// 				b.Put()
// 				return n, err
// 			}
// 			if _, err = vc.Write(b[:_n]); err != nil {
// 				b.Put()
// 				return n, err
// 			}
// 			n += int64(_n)
// 			if vc.writer.writeDirect {
// 				b.Put()
// 				break
// 			}
// 		}
// 	}
// 	// It is safe to get the TCPConn here, because writeDirect == true.
// 	conn, _ := getUnderlayTCPConnUnixConn(vc.Conn)
//  // Unsafe
// 	r_, _ := getUnderlayTCPConnUnixConn(r)
// 	_n, err := conn.(io.ReaderFrom).ReadFrom(r_.(io.Reader))
// 	// log.Println("Write", n, _n)
// 	n += _n
// 	return n, err
// }

func (vc *Conn) write(p []byte) (err error) {
	if vc.needHandshake {
		var prefix, suffix pool.PB
		vc.needHandshake = false
		if len(p) == 0 {
			prefix, suffix = ApplyPaddingFromPool(p, commandPaddingContinue, vc.userUUID, false)
		} else {
			vc.FilterTLS(p)
			// logrus.Println("isTLS", vc.isTLS)
			prefix, suffix = ApplyPaddingFromPool(p, commandPaddingContinue, vc.userUUID, vc.isTLS)
		}
		defer prefix.Put()
		defer suffix.Put()
		_, err = iout.MultiWrite(vc.writer, prefix, p, suffix)
		if err != nil {
			return err
		}
		if tlsConn, ok := vc.tlsConn.(*gotls.Conn); ok {
			if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else if utlsConn, ok := vc.tlsConn.(*utls.UConn); ok {
			if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
				return ErrNotTLS13
			}
		} else {
			panic("fixme")
		}
		vc.tlsConn = nil
		return nil
	}

	if vc.writeFilterApplicationData {
		p, p2 := ReshapeBytes(p)
		vc.FilterTLS(p)
		// logrus.Println("isTLS2:", vc.isTLS, len(p), len(p2))
		command := commandPaddingContinue
		if !vc.isTLS {
			command = commandPaddingEnd

			// disable XTLS
			//vc.readProcess = false
			vc.writeFilterApplicationData = false
			vc.packetsToFilter = 0
		} else if len(p) > 6 && bytes.Equal(p[:3], tlsApplicationDataStart) || vc.packetsToFilter <= 0 {
			command = commandPaddingEnd
			if vc.enableXTLS {
				command = commandPaddingDirect
				vc.toWriteDirect = true
			}
			vc.writeFilterApplicationData = false
		}
		// logrus.Println("command", commandPaddingDirect, "vc.writer.toWriteDirect", vc.writer.toWriteDirect)
		prefix, suffix := ApplyPaddingFromPool(p, command, nil, vc.isTLS)
		defer prefix.Put()
		defer suffix.Put()
		_, err = iout.MultiWrite(vc.writer, prefix, p, suffix)
		if err != nil {
			return err
		}
		// logrus.Println("command 2", commandPaddingDirect, "vc.writer.toWriteDirect", vc.writer.toWriteDirect)

		if vc.toWriteDirect {
			vc.writer.writeDirect = true
			// logrus.Infoln("XTLS Vision direct write start")
			// 	//time.Sleep(5 * time.Millisecond)
		}
		if p2 != nil {
			if vc.toWriteDirect || !vc.isTLS {
				_, err = vc.writer.Write(p2)
				return err
			}
			vc.FilterTLS(p)
			// logrus.Println("isTLS3", vc.isTLS)
			command = commandPaddingContinue
			if len(p) > 6 && bytes.Equal(p[:3], tlsApplicationDataStart) || vc.packetsToFilter <= 0 {
				command = commandPaddingEnd
				if vc.enableXTLS {
					command = commandPaddingDirect
					vc.toWriteDirect = true
				}
				vc.writeFilterApplicationData = false
			}
			// logrus.Println("command", commandPaddingDirect)
			prefix2, suffix2 := ApplyPaddingFromPool(p2, command, nil, vc.isTLS)
			defer prefix2.Put()
			defer suffix2.Put()
			_, err = iout.MultiWrite(vc.writer, prefix2, p2, suffix2)
			if vc.toWriteDirect {
				vc.writer.writeDirect = true
				// logrus.Debugln("XTLS Vision direct write start")
				// 	//time.Sleep(10 * time.Millisecond)
			}
		}
		return err
	}
	// if vc.toWriteDirect {
	// 	// logrus.Infof("XTLS Vision Direct write, payloadLen=%d", len(p))
	// }
	_, err = vc.writer.Write(p)
	return err
}
