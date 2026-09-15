package nitro

import (
	"fmt"
	"os"
	"strings"
)

const (
	// nsmHwRNG is the hwrng the Nitro Security Module driver registers.
	nsmHwRNG = "nsm-hwrng"
	// hwRNGCurrentPath holds the hwrng currently feeding the kernel entropy pool.
	hwRNGCurrentPath = "/sys/class/misc/hw_random/rng_current"
)

// VerifyEntropySource checks that the hardware RNG feeding the kernel entropy
// pool is the Nitro Security Module. Call before anything derives key material.
func VerifyEntropySource() error {
	current, err := os.ReadFile(hwRNGCurrentPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", hwRNGCurrentPath, err)
	}
	if name := strings.TrimSpace(string(current)); name != nsmHwRNG {
		return fmt.Errorf("hardware RNG is %q, want %q", name, nsmHwRNG)
	}
	return nil
}
