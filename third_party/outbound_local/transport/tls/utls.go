package tls

import (
	"crypto/tls"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

func uTLSConfigFromTLSConfig(config *tls.Config) *utls.Config {
	if config == nil {
		return nil
	}
	uConfig := &utls.Config{
		Rand:                   config.Rand,
		Time:                   config.Time,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     config.InsecureSkipVerify,
		RootCAs:                config.RootCAs,
		VerifyPeerCertificate:  config.VerifyPeerCertificate,
		KeyLogWriter:           config.KeyLogWriter,
		MinVersion:             config.MinVersion,
		MaxVersion:             config.MaxVersion,
		SessionTicketsDisabled: config.SessionTicketsDisabled,
		Renegotiation:          utls.RenegotiationSupport(config.Renegotiation),
	}
	if len(config.NextProtos) > 0 {
		uConfig.NextProtos = append([]string(nil), config.NextProtos...)
	}
	if len(config.CipherSuites) > 0 {
		uConfig.CipherSuites = append([]uint16(nil), config.CipherSuites...)
	}
	if len(config.CurvePreferences) > 0 {
		uConfig.CurvePreferences = make([]utls.CurveID, len(config.CurvePreferences))
		for i, curveID := range config.CurvePreferences {
			uConfig.CurvePreferences[i] = utls.CurveID(curveID)
		}
	}
	if clientSessionCache, ok := any(config.ClientSessionCache).(utls.ClientSessionCache); ok {
		uConfig.ClientSessionCache = clientSessionCache
	}
	return uConfig
}

var clientHelloIDMap = map[string]*utls.ClientHelloID{
	"random":            &utls.HelloRandomized,
	"randomized":        &utls.HelloRandomized,
	"randomizedalpn":    &utls.HelloRandomizedALPN,
	"randomizednoalpn":  &utls.HelloRandomizedNoALPN,
	"firefox":           &utls.HelloFirefox_Auto,
	"firefox_auto":      &utls.HelloFirefox_Auto,
	"firefox_55":        &utls.HelloFirefox_55,
	"firefox_56":        &utls.HelloFirefox_56,
	"firefox_63":        &utls.HelloFirefox_63,
	"firefox_65":        &utls.HelloFirefox_65,
	"firefox_99":        &utls.HelloFirefox_99,
	"firefox_102":       &utls.HelloFirefox_102,
	"firefox_105":       &utls.HelloFirefox_105,
	"chrome":            &utls.HelloChrome_Auto,
	"chrome_auto":       &utls.HelloChrome_Auto,
	"chrome_58":         &utls.HelloChrome_58,
	"chrome_62":         &utls.HelloChrome_62,
	"chrome_70":         &utls.HelloChrome_70,
	"chrome_72":         &utls.HelloChrome_72,
	"chrome_83":         &utls.HelloChrome_83,
	"chrome_87":         &utls.HelloChrome_87,
	"chrome_96":         &utls.HelloChrome_96,
	"chrome_100":        &utls.HelloChrome_100,
	"chrome_102":        &utls.HelloChrome_102,
	"ios":               &utls.HelloIOS_Auto,
	"ios_auto":          &utls.HelloIOS_Auto,
	"ios_11_1":          &utls.HelloIOS_11_1,
	"ios_12_1":          &utls.HelloIOS_12_1,
	"ios_13":            &utls.HelloIOS_13,
	"ios_14":            &utls.HelloIOS_14,
	"android_11_okhttp": &utls.HelloAndroid_11_OkHttp,
	"edge":              &utls.HelloEdge_Auto,
	"edge_auto":         &utls.HelloEdge_Auto,
	"edge_85":           &utls.HelloEdge_85,
	"edge_106":          &utls.HelloEdge_106,
	"safari":            &utls.HelloSafari_Auto,
	"safari_auto":       &utls.HelloSafari_Auto,
	"safari_16_0":       &utls.HelloSafari_16_0,
	"360":               &utls.Hello360_Auto,
	"360_auto":          &utls.Hello360_Auto,
	"360_7_5":           &utls.Hello360_7_5,
	"360_11_0":          &utls.Hello360_11_0,
	"qq":                &utls.HelloQQ_Auto,
	"qq_auto":           &utls.HelloQQ_Auto,
	"qq_11_1":           &utls.HelloQQ_11_1,
}

func nameToUtlsClientHelloID(name string) (*utls.ClientHelloID, error) {
	clientHelloID, ok := clientHelloIDMap[name]
	if !ok {
		return nil, fmt.Errorf("unknown uTLS Client Hello ID: %s", name)
	}
	return clientHelloID, nil
}

// UTLSConfigFromTLSConfig converts a stdlib TLS config into a uTLS config.
func UTLSConfigFromTLSConfig(config *tls.Config) *utls.Config {
	return uTLSConfigFromTLSConfig(config)
}

// NameToUTLSClientHelloID resolves a configured uTLS fingerprint name.
func NameToUTLSClientHelloID(name string) (*utls.ClientHelloID, error) {
	return nameToUtlsClientHelloID(name)
}
