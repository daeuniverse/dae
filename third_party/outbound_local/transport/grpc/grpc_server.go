package grpc

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"github.com/daeuniverse/outbound/pool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type ServerConn struct {
	localAddr net.Addr
	tun       proto.GunService_TunServer
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	muRecv    sync.Mutex // muReading protects recv
	muSend    sync.Mutex // muWriting protects send
	buf       []byte
	offset    int

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer
	ctxRead       context.Context
	cancelRead    func()
	ctxWrite      context.Context
	cancelWrite   func()
	ctx           context.Context
	cancel        func()
}

func NewServerConn(tun proto.GunService_TunServer, localAddr net.Addr) *ServerConn {
	ctx, cancel := context.WithCancel(context.Background())
	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxWrite, cancelWrite := context.WithCancel(context.Background())
	return &ServerConn{
		tun:         tun,
		localAddr:   localAddr,
		ctx:         ctx,
		cancel:      cancel,
		ctxRead:     ctxRead,
		cancelRead:  cancelRead,
		ctxWrite:    ctxWrite,
		cancelWrite: cancelWrite,
	}
}

func (c *ServerConn) Read(p []byte) (n int, err error) {
	select {
	case <-c.ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muReading.Lock()
	defer c.muReading.Unlock()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	// set 1 to avoid channel leak
	readDone := make(chan RecvResp, 1)
	// pass channel to the function to avoid closure leak
	go func(readDone chan RecvResp) {
		// FIXME: not really abort the send so there is some problems when recover
		c.muRecv.Lock()
		defer c.muRecv.Unlock()
		recv, e := c.tun.Recv()
		readDone <- RecvResp{
			hunk: recv,
			err:  e,
		}
	}(readDone)
	select {
	case <-c.ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case recvResp := <-readDone:
		err = recvResp.err
		if err != nil {
			if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
				err = io.EOF
			}
			return 0, err
		}
		n = copy(p, recvResp.hunk.Data)
		c.buf = pool.Get(len(recvResp.hunk.Data) - n)
		copy(c.buf, recvResp.hunk.Data[n:])
		c.offset = 0
		return n, nil
	}
}

func (c *ServerConn) Write(p []byte) (n int, err error) {
	select {
	case <-c.ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	// set 1 to avoid channel leak
	sendDone := make(chan error, 1)
	// pass channel to the function to avoid closure leak
	go func(sendDone chan error) {
		// FIXME: not really abort the send so there is some problems when recover
		c.muSend.Lock()
		defer c.muSend.Unlock()
		e := c.tun.Send(&proto.Hunk{Data: p})
		sendDone <- e
	}(sendDone)
	select {
	case <-c.ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case err = <-sendDone:
		if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
			err = io.EOF
		}
		return len(p), err
	}
}

func (c *ServerConn) Close() error {
	select {
	case <-c.ctx.Done():
	default:
		c.cancel()
	}
	return nil
}
func (c *ServerConn) LocalAddr() net.Addr {
	return c.localAddr
}
func (c *ServerConn) RemoteAddr() net.Addr {
	p, _ := peer.FromContext(c.tun.Context())
	return p.Addr
}

func (c *ServerConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())
		default:
		}
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer to make the c.readClosed and c.writeClosed with the new pointer (if it is)
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

func (c *ServerConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer to make the c.readClosed and c.writeClosed with the new pointer (if it is)
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
	}
	return nil
}

func (c *ServerConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

type Server struct {
	*grpc.Server
	LocalAddr  net.Addr
	HandleConn func(conn net.Conn) error
}

func (g Server) Tun(tun proto.GunService_TunServer) error {
	if err := g.HandleConn(NewServerConn(tun, g.LocalAddr)); err != nil {
		return err
	}
	return nil
}

func (g Server) TunDatagram(datagramServer proto.GunService_TunDatagramServer) error {
	return nil
}
