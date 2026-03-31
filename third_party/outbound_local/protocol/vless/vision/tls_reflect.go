package vision

import (
	"bytes"
	gotls "crypto/tls"
	"fmt"
	"net"
	"reflect"
	"sync"
	"unsafe"

	"github.com/daeuniverse/outbound/netproxy"
	outboundtls "github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

type visionTLSReadBuffers struct {
	input    *bytes.Reader
	rawInput *bytes.Buffer
}

type visionTLSBufferOffsets struct {
	input    uintptr
	rawInput uintptr
}

var visionTLSBufferOffsetCache sync.Map

func visionIntrinsicConn(conn netproxy.Conn) (net.Conn, netproxy.Conn, reflect.Type, unsafe.Pointer, error) {
	type intrinsicConn interface {
		IntrinsicConn() netproxy.Conn
	}

	iconn, ok := conn.(intrinsicConn)
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", conn)
	}
	ic := iconn.IntrinsicConn()
	switch tlsConn := ic.(type) {
	case *gotls.Conn:
		return tlsConn.NetConn(), tlsConn, reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn), nil
	case *utls.UConn:
		if tlsConn.Conn == nil {
			return nil, nil, nil, nil, fmt.Errorf("XTLS received nil embedded uTLS connection: %T", ic)
		}
		return tlsConn.NetConn(), tlsConn, reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn), nil
	case *outboundtls.RealityUConn:
		if tlsConn.UConn == nil || tlsConn.Conn == nil {
			return nil, nil, nil, nil, fmt.Errorf("XTLS received nil embedded REALITY connection: %T", ic)
		}
		return tlsConn.NetConn(), tlsConn.UConn, reflect.TypeOf(tlsConn.Conn).Elem(), unsafe.Pointer(tlsConn.Conn), nil
	default:
		return nil, nil, nil, nil, fmt.Errorf("XTLS only supports TLS and REALITY directly for now: %T", ic)
	}
}

func visionTLSBufferOffsetsFor(t reflect.Type) (visionTLSBufferOffsets, error) {
	if cached, ok := visionTLSBufferOffsetCache.Load(t); ok {
		return cached.(visionTLSBufferOffsets), nil
	}

	inputField, ok := t.FieldByName("input")
	if !ok {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS cannot locate %s.input field", t)
	}
	if inputField.Type != reflect.TypeOf(bytes.Reader{}) {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS unexpected %s.input type: %v", t, inputField.Type)
	}

	rawInputField, ok := t.FieldByName("rawInput")
	if !ok {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS cannot locate %s.rawInput field", t)
	}
	if rawInputField.Type != reflect.TypeOf(bytes.Buffer{}) {
		return visionTLSBufferOffsets{}, fmt.Errorf("XTLS unexpected %s.rawInput type: %v", t, rawInputField.Type)
	}

	offsets := visionTLSBufferOffsets{
		input:    inputField.Offset,
		rawInput: rawInputField.Offset,
	}
	visionTLSBufferOffsetCache.Store(t, offsets)
	return offsets, nil
}

func visionTLSReadBuffersFor(t reflect.Type, p unsafe.Pointer) (visionTLSReadBuffers, error) {
	offsets, err := visionTLSBufferOffsetsFor(t)
	if err != nil {
		return visionTLSReadBuffers{}, err
	}
	return visionTLSReadBuffers{
		input:    (*bytes.Reader)(unsafe.Add(p, offsets.input)),
		rawInput: (*bytes.Buffer)(unsafe.Add(p, offsets.rawInput)),
	}, nil
}
