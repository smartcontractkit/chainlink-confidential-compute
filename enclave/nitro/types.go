package nitro

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// HexBytes is a custom type that can unmarshal hex strings into a byte slice.
// It also marshals byte slices back to hex strings for JSON output. This allows us
// to more easily parse AWS Nitro Measurements, which use hex byte strings in JSON.
type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("HexBytes: cannot unmarshal JSON into string: %w", err)
	}

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("HexBytes: failed to decode hex string '%s': %w", s, err)
	}
	*h = decoded
	return nil
}

func (h HexBytes) MarshalJSON() ([]byte, error) {
	s := hex.EncodeToString(h)
	return json.Marshal(s)
}

// PCRs uses our custom HexBytes type for PCR values.
type PCRs struct {
	PCR0 HexBytes `json:"pcr0"`
	PCR1 HexBytes `json:"pcr1"`
	PCR2 HexBytes `json:"pcr2"`
}

type Measurements struct {
	Measurements PCRs `json:"Measurements"`
}
