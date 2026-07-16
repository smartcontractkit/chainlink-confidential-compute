package util

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
)

// GetRootCACertPEM connects to the given host and returns the root CA certificate
// from the server's certificate chain in PEM format.
func GetRootCACertPEM(host string) ([]byte, error) {
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", host, err)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned by %s", host)
	}

	// The last cert in the chain is typically the root (or closest to root)
	rootCert := certs[len(certs)-1]

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	}

	return pem.EncodeToMemory(pemBlock), nil
}
