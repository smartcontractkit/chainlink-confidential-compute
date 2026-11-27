//go:build unix

package crashdebug

import (
	"os"

	"golang.org/x/sys/unix"
)

// mapFile creates path at the given size and maps it shared and writable.
func mapFile(path string, size int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // the mapping outlives the descriptor
	if err := f.Truncate(int64(size)); err != nil {
		return nil, err
	}
	return unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
}

// MapRingReadOnly maps an existing ring file for reading. It fails until the
// app has sized the file.
func MapRingReadOnly(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // the mapping outlives the descriptor
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < ringHeaderSize {
		return nil, os.ErrNotExist
	}
	return unix.Mmap(int(f.Fd()), 0, int(info.Size()), unix.PROT_READ, unix.MAP_SHARED)
}
