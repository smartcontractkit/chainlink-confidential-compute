package proxyclient

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapSOCKSHostUnreachable(t *testing.T) {
	err := errors.New("socks connect tcp vsock:5001->example.invalid:443: unknown error host unreachable")
	require.ErrorIs(t, mapSOCKSError(err), syscall.EHOSTUNREACH)
}
