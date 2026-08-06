package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Item struct {
	Path string
	Name string
	Size int64
}

type Store struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
}

func New(dir string, maxBytes int64) (*Store, error) {
	if maxBytes < 1024*1024 {
		maxBytes = 256 * 1024 * 1024
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, maxBytes: maxBytes}, nil
}

func (s *Store) Enqueue(idempotencyKey string, payload []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := sanitizeKey(idempotencyKey)
	name := fmt.Sprintf("%020d-%s.json", time.Now().UTC().UnixNano(), key)
	path := filepath.Join(s.dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := s.trimLocked(); err != nil {
		return path, err
	}
	return path, nil
}

func (s *Store) List() ([]Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked()
}

func (s *Store) Read(item Item) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if filepath.Dir(item.Path) != filepath.Clean(s.dir) {
		return nil, errors.New("spool item outside spool directory")
	}
	return os.ReadFile(item.Path)
}

func (s *Store) Remove(item Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if filepath.Dir(item.Path) != filepath.Clean(s.dir) {
		return errors.New("spool item outside spool directory")
	}
	if err := os.Remove(item.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) Stats() (depth int64, bytes int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, err := s.listLocked()
	if err != nil {
		return 0, 0, err
	}
	for _, item := range items {
		bytes += item.Size
	}
	return int64(len(items)), bytes, nil
}

func (s *Store) listLocked() ([]Item, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		items = append(items, Item{
			Path: filepath.Join(s.dir, entry.Name()),
			Name: entry.Name(),
			Size: info.Size(),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func (s *Store) trimLocked() error {
	items, err := s.listLocked()
	if err != nil {
		return err
	}
	var total int64
	for _, item := range items {
		total += item.Size
	}
	for _, item := range items {
		if total <= s.maxBytes {
			break
		}
		if err := os.Remove(item.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		total -= item.Size
	}
	return nil
}

func sanitizeKey(key string) string {
	if key == "" {
		return "batch"
	}
	var b strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "batch"
	}
	return b.String()
}
