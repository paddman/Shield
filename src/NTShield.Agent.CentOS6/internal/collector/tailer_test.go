package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailerStartsAtEndAndPersistsOffset(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "messages")
	statePath := filepath.Join(dir, "tail.json")
	if err := os.WriteFile(logPath, []byte("old line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tailer, err := NewTailer(statePath, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := tailer.Read([]string{logPath})
	if err != nil || len(lines) != 0 {
		t.Fatalf("first read lines=%v err=%v", lines, err)
	}
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.WriteString("new line\n")
	_ = f.Close()
	lines, err = tailer.Read([]string{logPath})
	if err != nil || len(lines) != 1 || lines[0].Text != "new line" {
		t.Fatalf("second read lines=%v err=%v", lines, err)
	}

	reloaded, err := NewTailer(statePath, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	lines, err = reloaded.Read([]string{logPath})
	if err != nil || len(lines) != 0 {
		t.Fatalf("reloaded read lines=%v err=%v", lines, err)
	}
}

func TestTailerTruncatesOversizedLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "waf.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("x", 5000)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tailer, err := NewTailer(filepath.Join(dir, "state.json"), false, 4096)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := tailer.Read([]string{logPath})
	if err != nil || len(lines) != 1 || !lines[0].Truncated {
		t.Fatalf("lines=%v err=%v", lines, err)
	}
}
