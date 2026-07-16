package util

import "testing"

// canonical holds the four EIP-55 example addresses from the spec, in their
// checksummed form. HexToAddress(s).String() must return exactly these
// regardless of the input casing or 0x prefix.
var canonical = []string{
	"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
	"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
	"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
	"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	// All-caps and all-lowercase examples from EIP-55.
	"0x52908400098527886E0F7030069857D2E4169EE7",
	"0x8617E340B3D01FA5F11F306F4090FD50E238070D",
	"0xde709f2102306220921060314715629080e2fb77",
	"0x27b1fdb04752bbc536007a920d24acb045561c26",
}

func TestHexToAddress_EIP55Vectors(t *testing.T) {
	for _, want := range canonical {
		hexBody := want[2:] // drop 0x
		// Each form of the same address must normalize to the canonical checksum.
		inputs := map[string]string{
			"0x-prefixed canonical": want,
			"bare canonical":        hexBody,
			"bare lowercase":        toLowerHex(hexBody),
			"0x lowercase":          "0x" + toLowerHex(hexBody),
			"0X uppercase prefix":   "0X" + toLowerHex(hexBody),
		}
		for name, in := range inputs {
			if got := HexToAddress(in).String(); got != want {
				t.Errorf("%s: HexToAddress(%q).String() = %q, want %q", name, in, got, want)
			}
		}
	}
}

// TestHexToAddress_BareOwner mirrors the real call: chainlink hands the
// workflow owner as a bare 40-char lowercase hex string (no 0x prefix), and we
// must produce a 0x-prefixed 20-byte address that the relay DON's validator
// accepts.
func TestHexToAddress_BareOwner(t *testing.T) {
	got := HexToAddress("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").String()
	want := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if len(got) != 42 || got[:2] != "0x" {
		t.Fatalf("result %q is not a 0x-prefixed 20-byte hex address", got)
	}
}

func TestHexToAddress_Idempotent(t *testing.T) {
	for _, addr := range canonical {
		if got := HexToAddress(addr).String(); got != addr {
			t.Errorf("not idempotent: HexToAddress(%q).String() = %q", addr, got)
		}
	}
}

// TestHexToAddress_Padding documents the lenient right-align behavior of
// go-ethereum's HexToAddress/SetBytes: short inputs are left-padded with zero
// bytes.
func TestHexToAddress_Padding(t *testing.T) {
	// "1" -> 0x0000...0001 -> checksum has no letters, stays as-is.
	want := "0x0000000000000000000000000000000000000001"
	if got := HexToAddress("1").String(); got != want {
		t.Errorf("HexToAddress(%q).String() = %q, want %q", "1", got, want)
	}
	// Empty input -> zero address.
	wantZero := "0x0000000000000000000000000000000000000000"
	if got := HexToAddress("").String(); got != wantZero {
		t.Errorf("HexToAddress(%q).String() = %q, want %q", "", got, wantZero)
	}
}

func toLowerHex(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'F' {
			b[i] = c + 32
		}
	}
	return string(b)
}
