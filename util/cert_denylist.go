package util

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// ErrCertificateDenied is returned from a TLS handshake when the peer's chain
// includes a certificate whose public key is on the denylist.
var ErrCertificateDenied = errors.New("tls: peer certificate chain contains a denied public key")

type spkiHash = [sha256.Size]byte

// CertificateDenylist rejects TLS peers whose certificate chain includes a
// denied public key. Entries are SHA-256 hashes of a certificate's DER-encoded
// SubjectPublicKeyInfo, so every certificate issued for a key (including
// cross-signs and reissues) is matched. The list is consulted on every
// handshake and can be replaced at runtime. The zero value denies nothing.
type CertificateDenylist struct {
	denied atomic.Pointer[map[spkiHash]struct{}]
}

var defaultCertificateDenylist = &CertificateDenylist{}

// DefaultCertificateDenylist returns the process-wide denylist enforced by the
// enclave's outbound TLS clients.
func DefaultCertificateDenylist() *CertificateDenylist {
	return defaultCertificateDenylist
}

// Set replaces the denylist with the given hex-encoded SPKI SHA-256 hashes. An
// empty list clears it. If any entry is invalid the current list is unchanged.
func (d *CertificateDenylist) Set(hexHashes []string) error {
	denied := make(map[spkiHash]struct{}, len(hexHashes))
	for _, h := range hexHashes {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != sha256.Size {
			return fmt.Errorf("invalid public key hash %q: want %d hex-encoded bytes", h, sha256.Size)
		}
		denied[spkiHash(b)] = struct{}{}
	}
	d.denied.Store(&denied)
	return nil
}

// Len returns the number of denied public keys.
func (d *CertificateDenylist) Len() int {
	if p := d.denied.Load(); p != nil {
		return len(*p)
	}
	return 0
}

// VerifyConnection accepts the connection if at least one verified chain is
// free of denied keys. Without verified chains (verification skipped) it checks
// the certificates the peer presented.
func (d *CertificateDenylist) VerifyConnection(cs tls.ConnectionState) error {
	p := d.denied.Load()
	if p == nil || len(*p) == 0 {
		return nil
	}
	denied := *p
	if len(cs.VerifiedChains) == 0 {
		if containsDeniedKey(cs.PeerCertificates, denied) {
			return ErrCertificateDenied
		}
		return nil
	}
	for _, chain := range cs.VerifiedChains {
		if !containsDeniedKey(chain, denied) {
			return nil
		}
	}
	return ErrCertificateDenied
}

// TLSConfig returns a copy of base (or a new config if base is nil) that also
// enforces the denylist, after any VerifyConnection base already sets.
func (d *CertificateDenylist) TLSConfig(base *tls.Config) *tls.Config {
	cfg := &tls.Config{}
	if base != nil {
		cfg = base.Clone()
	}
	prev := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if prev != nil {
			if err := prev(cs); err != nil {
				return err
			}
		}
		return d.VerifyConnection(cs)
	}
	return cfg
}

// SPKIHash returns the hex-encoded SHA-256 hash of cert's SubjectPublicKeyInfo,
// the format CertificateDenylist.Set accepts.
func SPKIHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func containsDeniedKey(certs []*x509.Certificate, denied map[spkiHash]struct{}) bool {
	for _, c := range certs {
		if _, ok := denied[sha256.Sum256(c.RawSubjectPublicKeyInfo)]; ok {
			return true
		}
	}
	return false
}
