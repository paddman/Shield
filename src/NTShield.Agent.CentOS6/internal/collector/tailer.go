package collector

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type TailedLine struct {
	Path       string
	Text       string
	ObservedAt time.Time
	Truncated  bool
}

type tailState struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

type Tailer struct {
	mu         sync.Mutex
	statePath  string
	startAtEnd bool
	maxLine    int
	states     map[string]tailState
}

func NewTailer(statePath string, startAtEnd bool, maxLineBytes int) (*Tailer, error) {
	if maxLineBytes < 4096 {
		maxLineBytes = 256 * 1024
	}
	t := &Tailer{
		statePath:  statePath,
		startAtEnd: startAtEnd,
		maxLine:    maxLineBytes,
		states:     make(map[string]tailState),
	}
	if err := t.load(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tailer) Read(patterns []string) ([]TailedLine, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	paths := expandPaths(patterns)
	lines := make([]TailedLine, 0)
	var errs []string
	changed := false

	for _, path := range paths {
		fileLines, didChange, err := t.readFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
				errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			}
			continue
		}
		changed = changed || didChange
		lines = append(lines, fileLines...)
	}
	if changed {
		if err := t.save(); err != nil {
			errs = append(errs, "save offsets: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return lines, errors.New(strings.Join(errs, "; "))
	}
	return lines, nil
}

func (t *Tailer) readFile(path string) ([]TailedLine, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, nil
	}
	inode := inodeOf(info)
	state, exists := t.states[path]
	if !exists {
		state = tailState{Inode: inode}
		if t.startAtEnd {
			state.Offset = info.Size()
			t.states[path] = state
			return nil, true, nil
		}
	} else if state.Inode != inode || info.Size() < state.Offset {
		// Rotation or copy-truncate.
		state = tailState{Inode: inode, Offset: 0}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	if _, err := f.Seek(state.Offset, io.SeekStart); err != nil {
		return nil, false, err
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	out := make([]TailedLine, 0)
	offset := state.Offset
	for {
		text, consumed, complete, truncated, err := readLineLimited(reader, t.maxLine)
		if complete {
			offset += int64(consumed)
			out = append(out, TailedLine{
				Path:       path,
				Text:       text,
				ObservedAt: time.Now().UTC(),
				Truncated:  truncated,
			})
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, false, err
		}
	}
	newState := tailState{Offset: offset, Inode: inode}
	changed := newState != state
	t.states[path] = newState
	return out, changed, nil
}

func readLineLimited(r *bufio.Reader, max int) (text string, consumed int, complete bool, truncated bool, err error) {
	buf := make([]byte, 0, minInt(max, 4096))
	for {
		frag, readErr := r.ReadSlice('\n')
		consumed += len(frag)
		if len(buf) < max {
			remaining := max - len(buf)
			if len(frag) > remaining {
				truncated = true
			} else {
				remaining = len(frag)
			}
			buf = append(buf, frag[:remaining]...)
		} else if len(frag) > 0 {
			truncated = true
		}
		if consumed > max {
			truncated = true
		}

		switch readErr {
		case nil:
			buf = bytesTrimLineEnding(buf)
			if truncated {
				buf = append(buf, []byte(" [NTShield: line truncated]")...)
			}
			return string(buf), consumed, true, truncated, nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			// Do not commit a partial trailing line. It will be re-read when the
			// writer appends the newline on the next poll.
			return "", consumed, false, truncated, io.EOF
		default:
			return "", consumed, false, truncated, readErr
		}
	}
}

func bytesTrimLineEnding(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func expandPaths(patterns []string) []string {
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "*?[") {
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				seen[filepath.Clean(match)] = struct{}{}
			}
			continue
		}
		seen[filepath.Clean(pattern)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for path := range seen {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

func (t *Tailer) load() error {
	data, err := os.ReadFile(t.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read tail state: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, &t.states); err != nil {
		return fmt.Errorf("parse tail state: %w", err)
	}
	return nil
}

func (t *Tailer) save() error {
	if err := os.MkdirAll(filepath.Dir(t.statePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t.states, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := t.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, t.statePath)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
