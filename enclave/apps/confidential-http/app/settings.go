package app

import (
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

// Settings is the runtime config this app accepts from the host over vsock
// (POST /settings). Unknown fields are ignored.
//
//   - DeniedPublicKeyHashes: hex SHA-256 hashes of certificate
//     SubjectPublicKeyInfos that outbound TLS connections reject anywhere in
//     the peer's chain. Replaced as a unit on every injection; omitted clears it.
type Settings struct {
	DeniedPublicKeyHashes []string `json:"deniedPublicKeyHashes,omitempty"`
}

// InjectSettings applies settings injected by the host over vsock.
func (a *httpEnclaveApp) InjectSettings(raw json.RawMessage) error {
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("parsing settings: %w", err)
	}
	if err := util.DefaultCertificateDenylist().Set(s.DeniedPublicKeyHashes); err != nil {
		return fmt.Errorf("parsing denied public key hashes: %w", err)
	}
	return nil
}
