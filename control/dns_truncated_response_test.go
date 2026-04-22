package control

import (
	"net"
	"testing"

	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type dnsMsgCaptureWriter struct {
	msg *dnsmessage.Msg
}

func (w *dnsMsgCaptureWriter) LocalAddr() net.Addr  { return nil }
func (w *dnsMsgCaptureWriter) RemoteAddr() net.Addr { return nil }
func (w *dnsMsgCaptureWriter) WriteMsg(msg *dnsmessage.Msg) error {
	w.msg = msg.Copy()
	return nil
}
func (w *dnsMsgCaptureWriter) Write([]byte) (int, error) { return 0, nil }
func (w *dnsMsgCaptureWriter) Close() error              { return nil }
func (w *dnsMsgCaptureWriter) TsigStatus() error         { return nil }
func (w *dnsMsgCaptureWriter) TsigTimersOnly(bool)       {}
func (w *dnsMsgCaptureWriter) Hijack()                   {}

func TestDnsControllerSendDnsTruncatedResponse(t *testing.T) {
	ctrl := &DnsController{log: logrus.New()}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeAAAA)
	writer := &dnsMsgCaptureWriter{}

	require.NoError(t, ctrl.sendDnsTruncatedResponse_(msg, nil, writer))
	require.NotNil(t, writer.msg)
	require.True(t, writer.msg.Response)
	require.True(t, writer.msg.Truncated)
	require.Equal(t, dnsmessage.RcodeSuccess, writer.msg.Rcode)
	require.Empty(t, writer.msg.Answer)
	require.Len(t, writer.msg.Question, 1)
}
