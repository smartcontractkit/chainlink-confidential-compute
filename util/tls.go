package util

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// dialPeerCertificates connects to the given host over TLS and returns the
// certificates the peer presented.
func dialPeerCertificates(host string) ([]*x509.Certificate, error) {
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
	return certs, nil
}

// GetRootCACertPEM connects to the given host and returns the root CA certificate
// from the server's certificate chain in PEM format.
func GetRootCACertPEM(host string) ([]byte, error) {
	certs, err := dialPeerCertificates(host)
	if err != nil {
		return nil, err
	}

	// The last cert in the chain is typically the root (or closest to root)
	rootCert := certs[len(certs)-1]

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCert.Raw,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// GetPublicKeyHashes connects to the given host over TLS and returns the
// SHA-256 SPKI hash of each certificate in the peer's chain — the format
// CertificateDenylist.Set accepts.
func GetPublicKeyHashes(host string) ([]string, error) {
	certs, err := dialPeerCertificates(host)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(certs))
	for i, c := range certs {
		hashes[i] = SPKIHash(c)
	}
	return hashes, nil
}
