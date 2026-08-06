package parser

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SyslogMessage struct {
	Timestamp time.Time
	Facility  int
	Severity  int
	Hostname  string
	AppName   string
	ProcessID string
	Message   string
	Raw       string
	SourceIP  string
}

var (
	rfc3164RE = regexp.MustCompile(`^(?:<([0-9]{1,3})>)?([A-Z][a-z]{2})\s+([ 0-9][0-9])\s+([0-9]{2}:[0-9]{2}:[0-9]{2})\s+([^\s]+)\s+([^:]+):?\s?(.*)$`)
	tagPIDRE  = regexp.MustCompile(`^([^\[]+)(?:\[([^\]]+)\])?$`)
)

func ParseSyslog(raw string, receivedAt time.Time, source string) SyslogMessage {
	raw = strings.TrimRight(raw, "\r\n")
	out := SyslogMessage{
		Timestamp: receivedAt.UTC(),
		Facility:  -1,
		Severity:  -1,
		Message:   raw,
		Raw:       raw,
		SourceIP:  hostOnly(source),
	}

	if parseRFC5424(raw, &out) {
		return out
	}
	if parseRFC3164(raw, receivedAt, &out) {
		return out
	}
	return out
}

func parseRFC5424(raw string, out *SyslogMessage) bool {
	if !strings.HasPrefix(raw, "<") {
		return false
	}
	gt := strings.IndexByte(raw, '>')
	if gt < 2 || gt+2 >= len(raw) {
		return false
	}
	pri, err := strconv.Atoi(raw[1:gt])
	if err != nil || pri < 0 || pri > 191 {
		return false
	}
	rest := raw[gt+1:]
	space := strings.IndexByte(rest, ' ')
	if space < 1 {
		return false
	}
	version, err := strconv.Atoi(rest[:space])
	if err != nil || version < 1 || version > 999 {
		return false
	}

	// RFC 5424 fixed header: timestamp hostname app-name procid msgid.
	fields := make([]string, 0, 5)
	pos := space + 1
	for len(fields) < 5 {
		if pos >= len(rest) {
			return false
		}
		next := strings.IndexByte(rest[pos:], ' ')
		if next < 0 {
			return false
		}
		fields = append(fields, rest[pos:pos+next])
		pos += next + 1
	}

	out.Facility = pri / 8
	out.Severity = pri % 8
	if fields[0] != "-" {
		if ts, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
			out.Timestamp = ts.UTC()
		}
	}
	if fields[1] != "-" {
		out.Hostname = fields[1]
	}
	if fields[2] != "-" {
		out.AppName = fields[2]
	}
	if fields[3] != "-" {
		out.ProcessID = fields[3]
	}

	payload := rest[pos:]
	payload = stripStructuredData(payload)
	out.Message = strings.TrimSpace(payload)
	return true
}

func stripStructuredData(s string) string {
	s = strings.TrimLeft(s, " ")
	if s == "" || s[0] == '-' {
		if strings.HasPrefix(s, "-") {
			return strings.TrimLeft(s[1:], " ")
		}
		return s
	}
	if s[0] != '[' {
		return s
	}

	depth := 0
	quoted := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if quoted && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			continue
		}
		if quoted {
			continue
		}
		switch c {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				j := i + 1
				for j < len(s) && s[j] == '[' {
					// Multiple structured-data elements are contiguous. Continue.
					break
				}
				if j < len(s) && s[j] == '[' {
					continue
				}
				return strings.TrimLeft(s[j:], " ")
			}
		}
	}
	return s
}

func parseRFC3164(raw string, receivedAt time.Time, out *SyslogMessage) bool {
	m := rfc3164RE.FindStringSubmatch(raw)
	if m == nil {
		return false
	}
	if m[1] != "" {
		pri, err := strconv.Atoi(m[1])
		if err == nil && pri >= 0 && pri <= 191 {
			out.Facility = pri / 8
			out.Severity = pri % 8
		}
	}
	stamp := fmt.Sprintf("%04d %s %s %s", receivedAt.Year(), m[2], strings.TrimSpace(m[3]), m[4])
	if ts, err := time.ParseInLocation("2006 Jan 2 15:04:05", stamp, time.Local); err == nil {
		// Around New Year, RFC3164 has no year. Avoid interpreting Dec logs one year ahead.
		if ts.After(receivedAt.Add(24 * time.Hour)) {
			ts = ts.AddDate(-1, 0, 0)
		}
		out.Timestamp = ts.UTC()
	}
	out.Hostname = m[5]
	tag := strings.TrimSpace(m[6])
	if tm := tagPIDRE.FindStringSubmatch(tag); tm != nil {
		out.AppName = strings.TrimSpace(tm[1])
		out.ProcessID = tm[2]
	} else {
		out.AppName = tag
	}
	out.Message = m[7]
	return true
}

func hostOnly(source string) string {
	if source == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(source); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(source, "[]")
}
