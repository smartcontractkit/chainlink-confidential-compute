//go:build !unix

package crashdebug

import "errors"

func mapFile(string, int) ([]byte, error) {
	return nil, errors.New("crashdebug: shared mappings are not supported on this platform")
}

// MapRingReadOnly is unsupported on this platform.
func MapRingReadOnly(string) ([]byte, error) {
	return nil, errors.New("crashdebug: shared mappings are not supported on this platform")
}
