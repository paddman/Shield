package spool

import (
	"os"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue("abc", []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%v err=%v", items, err)
	}
	data, err := s.Read(items[0])
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if err := s.Remove(items[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(items[0].Path); !os.IsNotExist(err) {
		t.Fatalf("expected removed file, err=%v", err)
	}
}
