package util

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestCertificateDenylistSet(t *testing.T) {
	var d CertificateDenylist
	assert.Equal(t, 0, d.Len())

	cert := newTestCert(t, "a")
	require.NoError(t, d.Set([]string{SPKIHash(cert), " " + strings.ToUpper(SPKIHash(newTestCert(t, "b"))) + " "}))
	assert.Equal(t, 2, d.Len())

	require.Error(t, d.Set([]string{"not-hex"}))
	require.Error(t, d.Set([]string{"abcd"}))
	assert.Equal(t, 2, d.Len(), "invalid input leaves the list unchanged")

	require.NoError(t, d.Set(nil))
	assert.Equal(t, 0, d.Len())
}

func TestCertificateDenylistVerifyConnection(t *testing.T) {
	leaf, intermediate, altIntermediate, root := newTestCert(t, "leaf"), newTestCert(t, "int"), newTestCert(t, "alt"), newTestCert(t, "root")
	var d CertificateDenylist

	denied := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}}}
	require.NoError(t, d.VerifyConnection(denied), "empty list allows everything")

	require.NoError(t, d.Set([]string{SPKIHash(intermediate)}))
	require.ErrorIs(t, d.VerifyConnection(denied), ErrCertificateDenied)

	multi := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}, {leaf, altIntermediate, root}}}
	require.NoError(t, d.VerifyConnection(multi), "a clean alternate chain is accepted")

	unverified := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, intermediate}}
	require.ErrorIs(t, d.VerifyConnection(unverified), ErrCertificateDenied)
}

func TestCertificateDenylistTLSConfigChainsExistingCallback(t *testing.T) {
	var d CertificateDenylist
	called := false
	base := &tls.Config{MinVersion: tls.VersionTLS13, VerifyConnection: func(tls.ConnectionState) error {
		called = true
		return nil
	}}
	cfg := d.TLSConfig(base)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	require.NoError(t, cfg.VerifyConnection(tls.ConnectionState{}))
	assert.True(t, called)
	assert.NotSame(t, base, cfg)
}

func TestRestrictedHTTPClientEnforcesDefaultDenylist(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	t.Cleanup(func() { require.NoError(t, DefaultCertificateDenylist().Set(nil)) })

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client := NewRestrictedHTTPClientWithTLSAndDialer(&tls.Config{RootCAs: roots}, dial)

	resp, err := client.Get("https://example.com/")
	require.NoError(t, err)
	SafeClose(resp)

	require.NoError(t, DefaultCertificateDenylist().Set([]string{SPKIHash(srv.Certificate())}))
	_, err = client.Get("https://example.com/")
	require.ErrorIs(t, err, ErrCertificateDenied)

	require.NoError(t, DefaultCertificateDenylist().Set(nil))
	resp, err = client.Get("https://example.com/")
	require.NoError(t, err)
	SafeClose(resp)
}
