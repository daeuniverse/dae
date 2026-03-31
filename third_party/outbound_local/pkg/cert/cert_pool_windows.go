//go:build windows
// +build windows

package cert

import (
	"crypto/x509"
	"fmt"
	"syscall"
	"unsafe"
)

func GetSystemCertPool() (*x509.CertPool, error) {
	rootU16Ptr, err := syscall.UTF16PtrFromString("Root")
	if err != nil {
		return nil, err
	}
	storeHandle, err := syscall.CertOpenSystemStore(0, rootU16Ptr)
	if err != nil {
		fmt.Println(syscall.GetLastError())
		return nil, err
	}

	var certs []*x509.Certificate
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(storeHandle, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == 0x80092004 {
					break
				}
			}
			fmt.Println(syscall.GetLastError())
			return nil, err
		}
		if cert == nil {
			break
		}
		// Copy the buf, since ParseCertificate does not create its own copy.
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			certs = append(certs, c)
		}
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}
