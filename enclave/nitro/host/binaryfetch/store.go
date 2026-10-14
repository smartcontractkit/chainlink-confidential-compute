package binaryfetch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store is where cached binary bytes physically live. The enclave uses
// MemoryStore (RAM only, nothing leaves the TEE); the host uses DiskStore so a
// binary survives container restarts. Eviction policy is not the Store's
// concern -- Cache owns it and calls Delete.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Get returns the bytes stored under key.
	Get(key string) ([]byte, bool)
	// Put stores value under key, replacing any existing entry.
	Put(key string, value []byte) error
	// Delete removes key. Deleting an absent key is not an error.
	Delete(key string)
	// Entries returns the size in bytes of every entry currently held, so a
	// Cache can rebuild its eviction index over a store that outlived it.
	Entries() (map[string]int, error)
}

// MemoryStore keeps binaries in a map. Zero value is not usable; use
// NewMemoryStore.
type MemoryStore struct {
	mu    sync.RWMutex
	items map[string][]byte
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string][]byte)}
}

func (s *MemoryStore) Get(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[key]
	return v, ok
}

func (s *MemoryStore) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[key] = value
	return nil
}

func (s *MemoryStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
}

func (s *MemoryStore) Entries() (map[string]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.items))
	for k, v := range s.items {
		out[k] = len(v)
	}
	return out, nil
}

// binaryFileExt is appended to the key to form a cache filename.
const binaryFileExt = ".bin"

// DiskStore keeps binaries as files in a directory. Used by the host, where the
// directory is a node-local volume that outlives the container.
type DiskStore struct {
	dir string
}

var _ Store = (*DiskStore)(nil)

// NewDiskStore creates dir if needed and returns a Store rooted there.
func NewDiskStore(dir string) (*DiskStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("cache directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating cache dir %q: %w", dir, err)
	}
	return &DiskStore{dir: dir}, nil
}

// safeKey rejects keys that are not safe as a single path element. Keys
// originate in untrusted request data, so anything that could escape the cache
// directory or collide across entries is refused rather than sanitized.
func safeKey(key string) error {
	if key == "" {
		return fmt.Errorf("cache key is empty")
	}
	if len(key) > 128 {
		return fmt.Errorf("cache key too long")
	}
	for _, r := range key {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !isAlnum && r != '-' && r != '_' {
			return fmt.Errorf("cache key %q contains unsupported characters", key)
		}
	}
	return nil
}

// path resolves key to its file inside the cache directory. It re-validates the
// key and confirms the result is contained in s.dir, so a key that somehow got
// past safeKey still cannot escape the cache directory. Callers must treat an
// error as "no such entry" rather than falling back to an unchecked path.
func (s *DiskStore) path(key string) (string, error) {
	if err := safeKey(key); err != nil {
		return "", err
	}
	// safeKey restricts keys to [A-Za-z0-9_-], so Join cannot climb out of
	// s.dir; the containment check below makes that guarantee explicit rather
	// than implied by the character set.
	resolved := filepath.Clean(filepath.Join(s.dir, key+binaryFileExt))
	if filepath.Dir(resolved) != filepath.Clean(s.dir) {
		return "", fmt.Errorf("cache key %q escapes the cache directory", key)
	}
	return resolved, nil
}

func (s *DiskStore) Get(key string) ([]byte, bool) {
	path, err := s.path(key)
	if err != nil {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Put writes the binary via a temp file and renames it into place, so a crash
// or a concurrent reader never observes a partially written binary.
func (s *DiskStore) Put(key string, value []byte) error {
	path, err := s.path(key)
	if err != nil {
		return err
	}
	// The temp file is created from the validated path's base name, not the raw
	// key, so no caller-supplied string reaches the filesystem unchecked.
	tmp, err := os.CreateTemp(s.dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(value); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming into cache: %w", err)
	}
	return nil
}

func (s *DiskStore) Delete(key string) {
	path, err := s.path(key)
	if err != nil {
		return
	}
	_ = os.Remove(path)
}

// Entries lists the cache files left behind by a previous process, letting the
// Cache start warm with a correct byte count.
func (s *DiskStore) Entries() (map[string]int, error) {
	dirEntries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("reading cache dir: %w", err)
	}
	out := make(map[string]int, len(dirEntries))
	for _, e := range dirEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), binaryFileExt) {
			continue
		}
		key := strings.TrimSuffix(e.Name(), binaryFileExt)
		if safeKey(key) != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out[key] = int(info.Size())
	}
	return out, nil
}
