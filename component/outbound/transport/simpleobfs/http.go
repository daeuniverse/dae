// from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/http.go

package simpleobfs

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/daeuniverse/softwind/netproxy"
	"github.com/daeuniverse/softwind/pkg/fastrand"
	"github.com/daeuniverse/softwind/pool"
	"io"
	"net/http"
	"strings"
	"sync"
)

// HTTPObfs is shadowsocks http simple-obfs implementation
type HTTPObfs struct {
	netproxy.Conn
	host          string
	port          string
	path          string
	buf           []byte
	offset        int
	firstRequest  bool
	firstResponse bool
	wMu           sync.Mutex
	rMu           sync.Mutex
}

func (ho *HTTPObfs) Read(b []byte) (int, error) {
	ho.rMu.Lock()
	defer ho.rMu.Unlock()
	if ho.buf != nil {
		n := copy(b, ho.buf[ho.offset:])
		ho.offset += n
		if ho.offset == len(ho.buf) {
			pool.Put(ho.buf)
			ho.buf = nil
		}
		return n, nil
	}

	if ho.firstResponse {
		buf := pool.Get(1 << 15)
		n, err := ho.Conn.Read(buf)
		if err != nil {
			pool.Put(buf)
			return 0, err
		}
		idx := bytes.Index(buf[:n], []byte("\r\n\r\n"))
		if idx == -1 {
			pool.Put(buf)
			return 0, io.EOF
		}
		ho.firstResponse = false
		length := n - (idx + 4)
		n = copy(b, buf[idx+4:n])
		if length > n {
			ho.buf = buf[:idx+4+length]
			ho.offset = idx + 4 + n
		} else {
			pool.Put(buf)
		}
		return n, nil
	}
	return ho.Conn.Read(b)
}

func (ho *HTTPObfs) Write(b []byte) (int, error) {
	ho.wMu.Lock()
	defer ho.wMu.Unlock()
	if ho.firstRequest {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s%s", ho.host, ho.path), bytes.NewBuffer(b[:]))
		req.Header.Set("User-Agent", fmt.Sprintf("curl/7.%d.%d", fastrand.Rand().Int()%87, fastrand.Rand().Int()%2))
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		if ho.port != "80" {
			req.Host = fmt.Sprintf("%s:%s", ho.host, ho.port)
		}
		randBytes := make([]byte, 16)
		fastrand.Read(randBytes)
		req.Header.Set("Sec-WebSocket-Key", base64.URLEncoding.EncodeToString(randBytes))
		req.ContentLength = int64(len(b))
		err := req.Write(ho.Conn)
		ho.firstRequest = false
		return len(b), err
	}

	return ho.Conn.Write(b)
}

// NewHTTPObfs return a HTTPObfs
func NewHTTPObfs(conn netproxy.Conn, host string, port string, path string) netproxy.Conn {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &HTTPObfs{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
		host:          host,
		port:          port,
		path:          path,
	}
}
