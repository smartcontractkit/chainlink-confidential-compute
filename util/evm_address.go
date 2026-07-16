// Vendored verbatim from go-ethereum v1.17.3 so the enclave-app and
// capabilities/framework modules can produce EIP-55 checksummed addresses
// without pulling go-ethereum into the enclave TCB. Subset retained: just
// enough for HexToAddress(s).String(); everything else (Format, Marshal/
// Unmarshal, Scan, IsHexAddress, MixedcaseAddress, etc.) is omitted because
// no caller in this repo uses it.
//
// Each symbol below is copied byte-for-byte from these upstream files:
//
//	AddressLength       common/types.go:41   https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L41
//	Address             common/types.go:222  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L222
//	BytesToAddress      common/types.go:226  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L226-L230
//	HexToAddress        common/types.go:238  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L238
//	Address.Hex         common/types.go:261  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L261-L263
//	Address.String      common/types.go:266  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L266-L268
//	Address.checksumHex common/types.go:270  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L270-L289
//	Address.hex         common/types.go:291  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L291-L296
//	Address.SetBytes    common/types.go:328  https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/types.go#L328-L333
//	FromHex             common/bytes.go:29   https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/bytes.go#L29-L37
//	has0xPrefix         common/bytes.go:51   https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/bytes.go#L51-L53
//	Hex2Bytes           common/bytes.go:79   https://github.com/ethereum/go-ethereum/blob/v1.17.3/common/bytes.go#L79-L82
package util

import (
	"encoding/hex"

	keccak "golang.org/x/crypto/sha3"
)

// AddressLength is the expected length of the address
const AddressLength = 20

// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) Address { return BytesToAddress(FromHex(s)) }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	return string(a.checksumHex())
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}

func (a *Address) checksumHex() []byte {
	buf := a.hex()

	// compute checksum
	sha := keccak.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return buf[:]
}

func (a Address) hex() []byte {
	var buf [len(a)*2 + 2]byte
	copy(buf[:2], "0x")
	hex.Encode(buf[2:], a[:])
	return buf[:]
}

// SetBytes sets the address to the value of b.
// If b is larger than len(a), b will be cropped from the left.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// FromHex returns the bytes represented by the hexadecimal string s.
// s may be prefixed with "0x".
func FromHex(s string) []byte {
	if has0xPrefix(s) {
		s = s[2:]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return Hex2Bytes(s)
}

// has0xPrefix validates str begins with '0x' or '0X'.
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// Hex2Bytes returns the bytes represented by the hexadecimal string str.
func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}
