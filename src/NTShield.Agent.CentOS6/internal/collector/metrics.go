package collector

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Metrics struct {
	CPUPercent      *float64
	MemUsedPercent  *float64
	MemUsedBytes    int64
	MemTotalBytes   int64
	DiskUsedPercent *float64
	NetworkRXBPS    *float64
	NetworkTXBPS    *float64
	LoadAverage1    *float64
	ProcessRSSBytes int64
}

type MetricsCollector struct {
	mu           sync.Mutex
	lastAt       time.Time
	lastRX       uint64
	lastTX       uint64
	lastCPUTotal uint64
	lastCPUIdle  uint64
}

func (m *MetricsCollector) Snapshot() Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	out := Metrics{}
	if total, idle, err := readCPUStat(); err == nil {
		if m.lastCPUTotal > 0 && total > m.lastCPUTotal {
			deltaTotal := total - m.lastCPUTotal
			deltaIdle := idle - m.lastCPUIdle
			value := 100 * (1 - float64(deltaIdle)/float64(deltaTotal))
			if value < 0 {
				value = 0
			}
			if value > 100 {
				value = 100
			}
			out.CPUPercent = &value
		}
		m.lastCPUTotal, m.lastCPUIdle = total, idle
	}

	out.MemTotalBytes, out.MemUsedBytes, out.MemUsedPercent = readMemory()
	out.DiskUsedPercent = readDiskUsage("/")
	out.LoadAverage1 = readLoadAverage()
	out.ProcessRSSBytes = readProcessRSS()

	if rx, tx, err := readNetworkCounters(); err == nil {
		if !m.lastAt.IsZero() {
			seconds := now.Sub(m.lastAt).Seconds()
			if seconds > 0 && rx >= m.lastRX && tx >= m.lastTX {
				rxRate := float64(rx-m.lastRX) / seconds
				txRate := float64(tx-m.lastTX) / seconds
				out.NetworkRXBPS = &rxRate
				out.NetworkTXBPS = &txRate
			}
		}
		m.lastRX, m.lastTX = rx, tx
	}
	m.lastAt = now
	return out
}

func readCPUStat() (total, idle uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		return 0, 0, errors.New("empty /proc/stat")
	}
	fields := strings.Fields(s.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, errors.New("invalid /proc/stat cpu line")
	}
	for i := 1; i < len(fields); i++ {
		v, parseErr := strconv.ParseUint(fields[i], 10, 64)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		total += v
		if i == 4 || i == 5 { // idle + iowait
			idle += v
		}
	}
	return total, idle, nil
}

func readMemory() (totalBytes, usedBytes int64, usedPercent *float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, nil
	}
	vals := make(map[string]int64)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, _ := strconv.ParseInt(fields[1], 10, 64)
		vals[key] = value * 1024
	}
	total := vals["MemTotal"]
	available := vals["MemAvailable"]
	if available == 0 {
		available = vals["MemFree"] + vals["Buffers"] + vals["Cached"]
	}
	if total <= 0 {
		return 0, 0, nil
	}
	used := total - available
	if used < 0 {
		used = 0
	}
	pct := 100 * float64(used) / float64(total)
	return total, used, &pct
}

func readDiskUsage(path string) *float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return nil
	}
	used := st.Blocks - st.Bfree
	pct := 100 * float64(used) / float64(st.Blocks)
	return &pct
}

func readLoadAverage() *float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return nil
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return &value
}

func readNetworkCounters() (rx, tx uint64, err error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		r, rErr := strconv.ParseUint(fields[0], 10, 64)
		t, tErr := strconv.ParseUint(fields[8], 10, 64)
		if rErr == nil {
			rx += r
		}
		if tErr == nil {
			tx += t
		}
	}
	return rx, tx, s.Err()
}

func readProcessRSS() int64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * int64(os.Getpagesize())
}

func FormatMetrics(m Metrics) string {
	part := func(name string, value *float64, suffix string) string {
		if value == nil {
			return name + "=n/a"
		}
		return fmt.Sprintf("%s=%.1f%s", name, *value, suffix)
	}
	return strings.Join([]string{
		part("cpu", m.CPUPercent, "%"),
		part("mem", m.MemUsedPercent, "%"),
		part("disk", m.DiskUsedPercent, "%"),
		part("rx", m.NetworkRXBPS, "B/s"),
		part("tx", m.NetworkTXBPS, "B/s"),
		part("load1", m.LoadAverage1, ""),
	}, " ")
}
