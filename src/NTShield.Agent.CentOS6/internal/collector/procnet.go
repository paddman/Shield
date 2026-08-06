package collector

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
)

type socketRow struct {
	Protocol      string
	LocalAddress  string
	LocalPort     int
	RemoteAddress string
	RemotePort    int
	TCPState      *int
	UID           string
	Inode         string
}

type processInfo struct {
	PID         int
	Name        string
	Path        string
	CommandLine string
	Owner       string
	ParentPID   *int
}

type ProcNetCollector struct {
	mu             sync.Mutex
	maxConnections int
	collectClosed  bool
	previous       map[string]model.NetworkConnectionRecord
	procRoot       string
}

func NewProcNetCollector(maxConnections int, collectClosed bool) *ProcNetCollector {
	if maxConnections < 100 {
		maxConnections = 10000
	}
	return &ProcNetCollector{
		maxConnections: maxConnections,
		collectClosed:  collectClosed,
		previous:       make(map[string]model.NetworkConnectionRecord),
		procRoot:       "/proc",
	}
}

func (c *ProcNetCollector) Collect(agentID, computerName string) ([]model.NetworkConnectionRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rows := make([]socketRow, 0)
	var errs []string
	for _, spec := range []struct {
		file  string
		proto string
		ipv6  bool
	}{
		{"net/tcp", "TCP", false},
		{"net/tcp6", "TCP", true},
		{"net/udp", "UDP", false},
		{"net/udp6", "UDP", true},
	} {
		parsed, err := parseProcNetFile(filepath.Join(c.procRoot, spec.file), spec.proto, spec.ipv6, c.maxConnections-len(rows))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, spec.file+": "+err.Error())
		}
		rows = append(rows, parsed...)
		if len(rows) >= c.maxConnections {
			break
		}
	}

	wanted := make(map[string]struct{})
	for _, row := range rows {
		if row.Inode != "" && row.Inode != "0" {
			wanted[row.Inode] = struct{}{}
		}
	}
	procByInode := c.resolveProcesses(wanted)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	current := make(map[string]model.NetworkConnectionRecord, len(rows))
	out := make([]model.NetworkConnectionRecord, 0, len(rows))

	for _, row := range rows {
		proc := procByInode[row.Inode]
		key := connectionKey(row, proc.PID)
		record := model.NetworkConnectionRecord{
			TimestampUTC:       now,
			ComputerName:       computerName,
			AgentID:            agentID,
			Protocol:           row.Protocol,
			LocalAddress:       row.LocalAddress,
			LocalPort:          row.LocalPort,
			RemoteAddress:      row.RemoteAddress,
			RemotePort:         row.RemotePort,
			TCPState:           row.TCPState,
			ProcessID:          proc.PID,
			ProcessName:        proc.Name,
			ProcessPath:        proc.Path,
			ProcessCommandLine: proc.CommandLine,
			ProcessOwner:       proc.Owner,
			ParentProcessID:    proc.ParentPID,
			IsNew:              true,
			ConnectionKey:      key,
		}
		if _, existed := c.previous[key]; existed {
			record.IsNew = false
		}
		current[key] = record
		out = append(out, record)
	}

	if c.collectClosed {
		for key, old := range c.previous {
			if _, stillOpen := current[key]; stillOpen {
				continue
			}
			old.TimestampUTC = now
			old.IsNew = false
			old.IsClosed = true
			out = append(out, old)
			if len(out) >= c.maxConnections*2 {
				break
			}
		}
	}
	c.previous = current

	sort.Slice(out, func(i, j int) bool { return out[i].ConnectionKey < out[j].ConnectionKey })
	if len(errs) > 0 {
		return out, errors.New(strings.Join(errs, "; "))
	}
	return out, nil
}

func parseProcNetFile(path, protocol string, ipv6 bool, limit int) ([]socketRow, error) {
	if limit <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rows := make([]socketRow, 0)
	s := bufio.NewScanner(f)
	if s.Scan() { // header
	}
	for s.Scan() && len(rows) < limit {
		fields := strings.Fields(s.Text())
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, err := decodeProcEndpoint(fields[1], ipv6)
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := decodeProcEndpoint(fields[2], ipv6)
		if err != nil {
			continue
		}
		var state *int
		if strings.HasPrefix(protocol, "TCP") {
			if mapped, ok := mapLinuxTCPState(fields[3]); ok {
				v := mapped
				state = &v
			}
		}
		rows = append(rows, socketRow{
			Protocol:      protocol,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			TCPState:      state,
			UID:           fields[7],
			Inode:         fields[9],
		})
	}
	return rows, s.Err()
}

func decodeProcEndpoint(value string, ipv6 bool) (string, int, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid endpoint %q", value)
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	address, err := decodeProcAddress(parts[0], ipv6)
	return address, int(port64), err
}

func decodeProcAddress(value string, ipv6 bool) (string, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return "", err
	}
	if !ipv6 {
		if len(b) != 4 {
			return "", fmt.Errorf("invalid IPv4 address length: %d", len(b))
		}
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return net.IP(b).String(), nil
	}
	if len(b) != 16 {
		return "", fmt.Errorf("invalid IPv6 address length: %d", len(b))
	}
	// /proc/net/tcp6 stores each 32-bit word in host byte order.
	for word := 0; word < 4; word++ {
		start := word * 4
		b[start], b[start+3] = b[start+3], b[start]
		b[start+1], b[start+2] = b[start+2], b[start+1]
	}
	return net.IP(b).String(), nil
}

func mapLinuxTCPState(hexState string) (int, bool) {
	// NTShield.Shared.Enums.TcpConnectionState mirrors Windows MIB values.
	states := map[string]int{
		"01": 5,  // ESTABLISHED
		"02": 3,  // SYN_SENT
		"03": 4,  // SYN_RECV
		"04": 6,  // FIN_WAIT1
		"05": 7,  // FIN_WAIT2
		"06": 11, // TIME_WAIT
		"07": 1,  // CLOSE
		"08": 8,  // CLOSE_WAIT
		"09": 10, // LAST_ACK
		"0A": 2,  // LISTEN
		"0B": 9,  // CLOSING
		"0C": 4,  // NEW_SYN_RECV
	}
	v, ok := states[strings.ToUpper(hexState)]
	return v, ok
}

func connectionKey(row socketRow, pid int) string {
	raw := fmt.Sprintf("%s|%s|%d|%s|%d|%d|%s", row.Protocol, row.LocalAddress, row.LocalPort, row.RemoteAddress, row.RemotePort, pid, row.Inode)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

func (c *ProcNetCollector) resolveProcesses(wanted map[string]struct{}) map[string]processInfo {
	result := make(map[string]processInfo)
	if len(wanted) == 0 {
		return result
	}
	entries, err := os.ReadDir(c.procRoot)
	if err != nil {
		return result
	}
	ownerCache := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(c.procRoot, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		matched := make([]string, 0)
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := wanted[inode]; ok {
				matched = append(matched, inode)
			}
		}
		if len(matched) == 0 {
			continue
		}
		info := readProcessInfo(c.procRoot, pid, ownerCache)
		for _, inode := range matched {
			if _, exists := result[inode]; !exists {
				result[inode] = info
			}
		}
		if len(result) >= len(wanted) {
			break
		}
	}
	return result
}

func readProcessInfo(procRoot string, pid int, ownerCache map[string]string) processInfo {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	info := processInfo{PID: pid}
	if data, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		info.Name = strings.TrimSpace(string(data))
	}
	if path, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		info.Path = path
	}
	if data, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		info.CommandLine = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}
	if stat, err := os.Stat(base); err == nil {
		if sys, ok := stat.Sys().(interface{ Getuid() uint32 }); ok {
			uid := strconv.FormatUint(uint64(sys.Getuid()), 10)
			info.Owner = lookupOwner(uid, ownerCache)
		}
		// syscall.Stat_t does not expose a common interface method on all Go
		// targets, so Linux owner is filled below from /proc/<pid>/status too.
	}
	if data, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.Owner = lookupOwner(fields[1], ownerCache)
				}
			}
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if ppid, err := strconv.Atoi(fields[1]); err == nil {
						info.ParentPID = &ppid
					}
				}
			}
		}
	}
	return info
}

func lookupOwner(uid string, cache map[string]string) string {
	if value, ok := cache[uid]; ok {
		return value
	}
	value := uid
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		value = u.Username
	}
	cache[uid] = value
	return value
}
