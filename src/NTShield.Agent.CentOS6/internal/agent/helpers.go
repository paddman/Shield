package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func resolveAgentID(configured, stateDir string) (string, error) {
	if id := strings.TrimSpace(configured); id != "" {
		return id, nil
	}
	path := filepath.Join(stateDir, "agent-id")
	if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) != "" {
		return strings.TrimSpace(string(data)), nil
	}
	hostname, _ := os.Hostname()
	identity := ""
	for _, candidate := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(candidate); err == nil && strings.TrimSpace(string(data)) != "" {
			identity = strings.TrimSpace(string(data))
			break
		}
	}
	if identity == "" {
		identity = hostname
	}
	sum := sha256.Sum256([]byte(hostname + "|" + identity + "|ntshield-centos6"))
	id := hex.EncodeToString(sum[:8])
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0600); err != nil {
		return "", err
	}
	return id, nil
}

func detectOSVersion() string {
	release := "Linux"
	for _, path := range []string{"/etc/redhat-release", "/etc/centos-release", "/etc/system-release"} {
		if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) != "" {
			release = strings.TrimSpace(string(data))
			break
		}
	}
	kernel := ""
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}
	if kernel != "" {
		return release + "; kernel " + kernel
	}
	return release
}

func primaryHostIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

func sha256File(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func randomID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err == nil {
		return hex.EncodeToString(buf)
	}
	fallback := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())))
	return hex.EncodeToString(fallback[:16])
}

func splitDatagram(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func hostOnly(remote string) string {
	if remote == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(remote, "[]")
}

func sanitizeRuleID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "UNCLASSIFIED"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() >= 80 {
			break
		}
	}
	if b.Len() == 0 {
		return "UNCLASSIFIED"
	}
	return b.String()
}

func truncate(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
