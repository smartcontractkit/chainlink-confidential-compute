package attestor

import (
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

type nitroAttestor struct {
	session *nsm.Session
}

var _ Attestor = (*nitroAttestor)(nil)

func NewNitroAttestor(session *nsm.Session) *nitroAttestor {
	return &nitroAttestor{
		session: session,
	}
}

// CreateAttestation creates an attestation document using the NSM session.
// It currently does not use the nonce or public key fields, although these could be added to attestations in the future.
func (a *nitroAttestor) CreateAttestation(data []byte) ([]byte, error) {
	resp, err := a.session.Send(&request.Attestation{
		UserData: data,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("attestation error: %s", resp.Error)
	}

	if resp.Attestation == nil || resp.Attestation.Document == nil {
		return nil, fmt.Errorf("no attestation document produced")
	}

	return resp.Attestation.Document, nil
}
