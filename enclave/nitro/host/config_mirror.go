package main

import (
	"bytes"
	"slices"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// configMirror is the host's copy of the enclave's per-DON configs, learned
// from enclave responses. It needs no DON names: a signer belongs to exactly
// one config. The enclave re-checks everything, so a stale mirror only costs
// liveness until the next response for that DON corrects it.
// Not safe for concurrent use.
type configMirror struct {
	configs []types.EnclaveConfig
}

// insert stores cfg, dropping stored configs that share a signer with it:
// those predate cfg, e.g. a node that moved between shards.
func (m *configMirror) insert(cfg types.EnclaveConfig) {
	m.configs = slices.DeleteFunc(m.configs, func(old types.EnclaveConfig) bool {
		return slices.ContainsFunc(old.Signers, func(s []byte) bool {
			return slices.ContainsFunc(cfg.Signers, func(n []byte) bool { return bytes.Equal(s, n) })
		})
	})
	m.configs = append(m.configs, cfg.Copy())
}

// lookup returns the config that contains signer.
func (m *configMirror) lookup(signer []byte) (types.EnclaveConfig, bool) {
	for _, cfg := range m.configs {
		if containsSigner(cfg, signer) {
			return cfg.Copy(), true
		}
	}
	return types.EnclaveConfig{}, false
}

func (m *configMirror) allSigners() [][]byte {
	var signers [][]byte
	for _, cfg := range m.configs {
		signers = append(signers, cfg.Signers...)
	}
	return signers
}

func (m *configMirror) len() int { return len(m.configs) }

func (m *configMirror) clone() *configMirror {
	out := &configMirror{}
	for _, cfg := range m.configs {
		out.configs = append(out.configs, cfg.Copy())
	}
	return out
}

func containsSigner(cfg types.EnclaveConfig, signer []byte) bool {
	return slices.ContainsFunc(cfg.Signers, func(s []byte) bool { return bytes.Equal(s, signer) })
}
