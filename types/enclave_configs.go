package types

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

var shardSuffix = regexp.MustCompile(`^(.+)_shard-(\d+)$`)

// ParseCapRegDONName splits a CapReg DON name ("<name>_shard-N") into the
// workflow DON name the gateway routes by and the shard index. A name without
// the suffix is shard 0.
func ParseCapRegDONName(capRegDONName string) (workflowDONName string, shardIndex int) {
	m := shardSuffix.FindStringSubmatch(capRegDONName)
	if m == nil {
		return capRegDONName, 0
	}
	idx, err := strconv.Atoi(m[2])
	if err != nil {
		return capRegDONName, 0
	}
	return m[1], idx
}

// EnclaveConfigs holds one EnclaveConfig per workflow DON, by CapReg DON name.
// Signers are disjoint across DONs, so a signer identifies its DON.
// The empty name is the single config set by a client without per-DON configs.
// Not safe for concurrent use.
type EnclaveConfigs struct {
	configs   map[string]EnclaveConfig
	signerDON map[[32]byte]string
}

func NewEnclaveConfigs() *EnclaveConfigs {
	return &EnclaveConfigs{
		configs:   make(map[string]EnclaveConfig),
		signerDON: make(map[[32]byte]string),
	}
}

func (c *EnclaveConfigs) Len() int { return len(c.configs) }

func (c *EnclaveConfigs) Get(donName string) (EnclaveConfig, bool) {
	cfg, ok := c.configs[donName]
	if !ok {
		return EnclaveConfig{}, false
	}
	return cfg.Copy(), true
}

// Set stores cfg for donName. It fails if any signer already belongs to another DON.
func (c *EnclaveConfigs) Set(donName string, cfg EnclaveConfig) error {
	for _, s := range cfg.Signers {
		if other, ok := c.signerDON[sha256.Sum256(s)]; ok && other != donName {
			return fmt.Errorf("signer %x already belongs to DON %q", s, other)
		}
	}
	c.Delete(donName)
	cfg = cfg.Copy()
	c.configs[donName] = cfg
	for _, s := range cfg.Signers {
		c.signerDON[sha256.Sum256(s)] = donName
	}
	return nil
}

func (c *EnclaveConfigs) Delete(donName string) {
	old, ok := c.configs[donName]
	if !ok {
		return
	}
	for _, s := range old.Signers {
		delete(c.signerDON, sha256.Sum256(s))
	}
	delete(c.configs, donName)
}

// DONForSigner returns the name of the DON whose config contains signer.
func (c *EnclaveConfigs) DONForSigner(signer []byte) (string, bool) {
	donName, ok := c.signerDON[sha256.Sum256(signer)]
	return donName, ok
}

// AllSigners returns the signers of every config.
func (c *EnclaveConfigs) AllSigners() [][]byte {
	var signers [][]byte
	for _, donName := range c.DONNames() {
		signers = append(signers, c.configs[donName].Signers...)
	}
	return signers
}

// DONNames returns the DON names in sorted order.
func (c *EnclaveConfigs) DONNames() []string {
	names := make([]string, 0, len(c.configs))
	for n := range c.configs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Default returns the config served to clients that do not name a DON: the
// only config, or else the only shard-0 config.
func (c *EnclaveConfigs) Default() (string, EnclaveConfig, bool) {
	if len(c.configs) == 1 {
		for k, cfg := range c.configs {
			return k, cfg.Copy(), true
		}
	}
	var found string
	n := 0
	for k := range c.configs {
		if _, shard := ParseCapRegDONName(k); shard == 0 {
			found = k
			n++
		}
	}
	if n != 1 {
		return "", EnclaveConfig{}, false
	}
	cfg := c.configs[found]
	return found, cfg.Copy(), true
}

// Lookup returns the config for a client that asked for donName: an exact
// match, or the legacy config when it is the only one.
func (c *EnclaveConfigs) Lookup(donName string) (EnclaveConfig, bool) {
	if cfg, ok := c.Get(donName); ok {
		return cfg, true
	}
	if len(c.configs) == 1 {
		return c.Get("")
	}
	return EnclaveConfig{}, false
}

// Snapshot returns a copy of all configs by DON name.
func (c *EnclaveConfigs) Snapshot() map[string]EnclaveConfig {
	out := make(map[string]EnclaveConfig, len(c.configs))
	for k, cfg := range c.configs {
		out[k] = cfg.Copy()
	}
	return out
}

// Clone returns an independent copy.
func (c *EnclaveConfigs) Clone() *EnclaveConfigs {
	out := NewEnclaveConfigs()
	for k, cfg := range c.configs {
		_ = out.Set(k, cfg)
	}
	return out
}
