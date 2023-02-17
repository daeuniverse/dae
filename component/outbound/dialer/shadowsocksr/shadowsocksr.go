package shadowsocksr

import (
	"encoding/base64"
	"fmt"
	"github.com/mzz2017/softwind/protocol"
	"github.com/mzz2017/softwind/protocol/direct"
	"github.com/mzz2017/softwind/protocol/shadowsocks_stream"
	"github.com/mzz2017/softwind/transport/shadowsocksr/obfs"
	"github.com/mzz2017/softwind/transport/shadowsocksr/proto"
	"github.com/v2rayA/dae/common"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	dialer.FromLinkRegister("shadowsocksr", NewShadowsocksR)
	dialer.FromLinkRegister("ssr", NewShadowsocksR)
}

type ShadowsocksR struct {
	Name       string `json:"name"`
	Server     string `json:"server"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	Cipher     string `json:"cipher"`
	Proto      string `json:"proto"`
	ProtoParam string `json:"protoParam"`
	Obfs       string `json:"obfs"`
	ObfsParam  string `json:"obfsParam"`
	Protocol   string `json:"protocol"`
}

func NewShadowsocksR(option *dialer.GlobalOption, iOption dialer.InstanceOption, link string) (*dialer.Dialer, error) {
	s, err := ParseSSRURL(link)
	if err != nil {
		return nil, err
	}
	return s.Dialer(option, iOption)
}

func (s *ShadowsocksR) Dialer(option *dialer.GlobalOption, iOption dialer.InstanceOption) (*dialer.Dialer, error) {
	d := direct.SymmetricDirect
	obfsDialer, err := obfs.NewDialer(d, &obfs.ObfsParam{
		ObfsHost:  s.Server,
		ObfsPort:  uint16(s.Port),
		Obfs:      s.Obfs,
		ObfsParam: s.ObfsParam,
	})
	if err != nil {
		return nil, err
	}
	d = obfsDialer
	d, err = shadowsocks_stream.NewDialer(d, protocol.Header{
		ProxyAddress:   net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Cipher:         s.Cipher,
		Password:       s.Password,
		IsClient:       true,
		ShouldFullCone: false,
	})
	if err != nil {
		return nil, err
	}
	d = &proto.Dialer{
		NextDialer:    d,
		Protocol:      s.Proto,
		ProtocolParam: s.ProtoParam,
		ObfsOverhead:  obfsDialer.ObfsOverhead(),
	}

	return dialer.NewDialer(d, option, iOption, s.Name, s.Protocol, s.ExportToURL()), nil
}

func ParseSSRURL(u string) (data *ShadowsocksR, err error) {
	// parse attempts to parse ss:// links
	parse := func(content string) (v ShadowsocksR, ok bool) {
		arr := strings.Split(content, "/?")
		if strings.Contains(content, ":") && len(arr) < 2 {
			content += "/?remarks=&protoparam=&obfsparam="
			arr = strings.Split(content, "/?")
		} else if len(arr) != 2 {
			return v, false
		}
		pre := strings.Split(arr[0], ":")
		if len(pre) > 6 {
			//if the length is more than 6, it means that the host contains the characters:,
			//re-merge the first few groups into the host
			pre[len(pre)-6] = strings.Join(pre[:len(pre)-5], ":")
			pre = pre[len(pre)-6:]
		} else if len(pre) < 6 {
			return v, false
		}
		q, err := url.ParseQuery(arr[1])
		if err != nil {
			return v, false
		}
		pswd, _ := common.Base64UrlDecode(pre[5])
		add, _ := common.Base64UrlDecode(pre[0])
		remarks, _ := common.Base64UrlDecode(q.Get("remarks"))
		protoparam, _ := common.Base64UrlDecode(q.Get("protoparam"))
		obfsparam, _ := common.Base64UrlDecode(q.Get("obfsparam"))
		port, err := strconv.Atoi(pre[1])
		if err != nil {
			return v, false
		}
		v = ShadowsocksR{
			Name:       remarks,
			Server:     add,
			Port:       port,
			Password:   pswd,
			Cipher:     pre[3],
			Proto:      pre[2],
			ProtoParam: protoparam,
			Obfs:       pre[4],
			ObfsParam:  obfsparam,
			Protocol:   "shadowsocksr",
		}
		return v, true
	}
	content := u[6:]
	var (
		info ShadowsocksR
		ok   bool
	)
	// try parsing the ssr:// link, if it fails, base64 decode first
	if info, ok = parse(content); !ok {
		// perform base64 decoding and parse again
		content, err = common.Base64StdDecode(content)
		if err != nil {
			content, err = common.Base64UrlDecode(content)
			if err != nil {
				return
			}
		}
		info, ok = parse(content)
	}
	if !ok {
		err = fmt.Errorf("%w: unrecognized ssr address", dialer.InvalidParameterErr)
		return
	}
	return &info, nil
}

func (s *ShadowsocksR) ExportToURL() string {
	/* ssr://server:port:proto:method:obfs:URLBASE64(password)/?remarks=URLBASE64(remarks)&protoparam=URLBASE64(protoparam)&obfsparam=URLBASE64(obfsparam)) */
	return fmt.Sprintf("ssr://%v", strings.TrimSuffix(base64.URLEncoding.EncodeToString([]byte(
		fmt.Sprintf(
			"%v:%v:%v:%v:%v/?remarks=%v&protoparam=%v&obfsparam=%v",
			net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
			s.Proto,
			s.Cipher,
			s.Obfs,
			base64.URLEncoding.EncodeToString([]byte(s.Password)),
			base64.URLEncoding.EncodeToString([]byte(s.Name)),
			base64.URLEncoding.EncodeToString([]byte(s.ProtoParam)),
			base64.URLEncoding.EncodeToString([]byte(s.ObfsParam)),
		),
	)), "="))
}
