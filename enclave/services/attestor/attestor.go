// This package provides the cloud provider-agnostic `Attestor` interface for creating remote attestations.
// It also provides an implementation that uses the NSM (Nitro Security Module) package to produce AWS Nitro attestations.

package attestor

type Attestor interface {
	CreateAttestation(data []byte) ([]byte, error)
}
