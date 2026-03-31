package meek

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type assemblerClient struct {
	tripper Tripper

	config *config
}

func newAssemblerClient(tripper Tripper, config *config) *assemblerClient {
	return &assemblerClient{
		tripper: tripper,
		config:  config,
	}
}

func (c *assemblerClient) NewSession(ctx context.Context) (Session, error) {
	sessionID := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, sessionID)
	if err != nil {
		return nil, err
	}

	sessionContext, finish := context.WithCancel(ctx)

	session := &assemblerClientSession{
		sessionID:  sessionID,
		ctx:        sessionContext,
		tripper:    c.tripper,
		finish:     finish,
		readBuffer: bytes.NewBuffer(nil),
		writerChan: make(chan []byte),
		readerChan: make(chan []byte, 16),
		assembler:  c,
	}

	go session.keepRunning()

	return session, nil
}

type assemblerClientSession struct {
	sessionID        []byte
	currentWriteWait int

	assembler  *assemblerClient
	tripper    Tripper
	readBuffer *bytes.Buffer
	writerChan chan []byte
	readerChan chan []byte
	ctx        context.Context
	finish     func()
}

func (s *assemblerClientSession) SetDeadline(t time.Time) error {
	return nil
}

func (s *assemblerClientSession) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *assemblerClientSession) SetWriteDeadline(t time.Time) error {
	return nil
}

func (s *assemblerClientSession) keepRunning() {
	s.currentWriteWait = int(s.assembler.config.InitialPollingIntervalMs)
	for s.ctx.Err() == nil {
		s.runOnce()
	}
}

func (s *assemblerClientSession) runOnce() {
	sendBuffer := bytes.NewBuffer(nil)
	if s.currentWriteWait != 0 {
		waitTimer := time.NewTimer(time.Millisecond * time.Duration(s.currentWriteWait))
		waitForFirstWrite := true
	copyFromWriterLoop:
		for {
			select {
			case <-s.ctx.Done():
				return
			case data := <-s.writerChan:
				sendBuffer.Write(data)
				if sendBuffer.Len() >= int(s.assembler.config.MaxWriteSize) {
					break copyFromWriterLoop
				}
				if waitForFirstWrite {
					waitForFirstWrite = false
					waitTimer.Reset(time.Millisecond * time.Duration(s.assembler.config.WaitSubsequentWriteMs))
				}
			case <-waitTimer.C:
				break copyFromWriterLoop
			}
		}
		waitTimer.Stop()
	}

	firstRound := true
	pollConnection := true
	for sendBuffer.Len() != 0 || firstRound {
		firstRound = false
		sendAmount := sendBuffer.Len()
		if sendAmount > int(s.assembler.config.MaxWriteSize) {
			sendAmount = int(s.assembler.config.MaxWriteSize)
		}
		data := sendBuffer.Next(sendAmount)
		if len(data) != 0 {
			pollConnection = false
		}
		for {
			ctx, cancel := netproxy.NewDialTimeoutContextFrom(s.ctx)
			defer cancel()
			resp, err := s.tripper.RoundTrip(ctx, Request{Data: data, ConnectionTag: s.sessionID})
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(time.Millisecond * time.Duration(s.assembler.config.FailedRetryIntervalMs))
				continue
			}
			if len(resp.Data) != 0 {
				s.readerChan <- resp.Data
			}
			if len(resp.Data) != 0 {
				pollConnection = false
			}
			break
		}
	}
	if pollConnection {
		s.currentWriteWait = int(s.assembler.config.BackoffFactor * float32(s.currentWriteWait))
		if s.currentWriteWait > int(s.assembler.config.MaxPollingIntervalMs) {
			s.currentWriteWait = int(s.assembler.config.MaxPollingIntervalMs)
		}
		if s.currentWriteWait < int(s.assembler.config.MinPollingIntervalMs) {
			s.currentWriteWait = int(s.assembler.config.MinPollingIntervalMs)
		}
	} else {
		s.currentWriteWait = int(0)
	}
}

func (s *assemblerClientSession) Read(p []byte) (n int, err error) {
	if s.readBuffer.Len() == 0 {
		select {
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		case data := <-s.readerChan:
			s.readBuffer.Write(data)
		}
	}
	n, err = s.readBuffer.Read(p)
	if err == io.EOF {
		s.readBuffer.Reset()
		return 0, nil
	}
	return
}

func (s *assemblerClientSession) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	case s.writerChan <- buf:
		return len(p), nil
	}
}

func (s *assemblerClientSession) Close() error {
	s.finish()
	return nil
}
