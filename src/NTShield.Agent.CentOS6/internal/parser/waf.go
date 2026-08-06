package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type WAFEvent struct {
	Timestamp  time.Time
	Provider   string
	RuleID     string
	Message    string
	Severity   int
	Action     string
	SourceIP   string
	SourcePort int
	Host       string
	URI        string
	UniqueID   string
	Raw        string
}

type auditBuffer struct {
	transaction string
	lines       []string
	bytes       int
	truncated   bool
}

type WAFAccumulator struct {
	mu       sync.Mutex
	buffers  map[string]*auditBuffer
	maxBytes int
}

var (
	auditBoundaryRE = regexp.MustCompile(`^--([A-Za-z0-9_-]+)-([A-Z])--\s*$`)
	idRE            = regexp.MustCompile(`(?i)\[id\s+"([^"]+)"\]`)
	msgRE           = regexp.MustCompile(`(?i)\[msg\s+"([^"]+)"\]`)
	severityRE      = regexp.MustCompile(`(?i)\[severity\s+"([^"]+)"\]`)
	hostnameRE      = regexp.MustCompile(`(?i)\[hostname\s+"([^"]+)"\]`)
	uriRE           = regexp.MustCompile(`(?i)\[uri\s+"([^"]+)"\]`)
	uniqueIDRE      = regexp.MustCompile(`(?i)\[unique_id\s+"([^"]+)"\]`)
	clientRE        = regexp.MustCompile(`(?i)\[client\s+([^\]\s]+)\]`)
	requestLineRE   = regexp.MustCompile(`(?m)^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/[0-9.]+\s*$`)
	auditARecordRE  = regexp.MustCompile(`(?m)^\[[^\]]+\]\s+\S+\s+([^\s]+)\s+([0-9]+)\s+([^\s]+)\s+([0-9]+)\s*$`)
	authorizationRE = regexp.MustCompile(`(?im)^(Authorization|Proxy-Authorization):\s*.*$`)
	cookieRE        = regexp.MustCompile(`(?im)^(Cookie|Set-Cookie):\s*.*$`)
	jsonSecretRE    = regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|authorization|cookie)"\s*:\s*)"[^"]*"`)
)

func NewWAFAccumulator(maxBytes int) *WAFAccumulator {
	if maxBytes < 4096 {
		maxBytes = 512 * 1024
	}
	return &WAFAccumulator{buffers: make(map[string]*auditBuffer), maxBytes: maxBytes}
}

// Feed accepts one tailed line. It emits a completed ModSecurity audit
// transaction or a single-line WAF event. Ordinary web-server lines are ignored.
func (a *WAFAccumulator) Feed(source, line string, receivedAt time.Time) []WAFEvent {
	a.mu.Lock()
	defer a.mu.Unlock()

	if m := auditBoundaryRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
		tx, section := m[1], m[2]
		key := source
		if section == "A" {
			a.buffers[key] = &auditBuffer{transaction: tx, lines: []string{line}, bytes: len(line) + 1}
			return nil
		}
		buf := a.buffers[key]
		if buf == nil || buf.transaction != tx {
			// A rotated/truncated audit file may begin in the middle of a transaction.
			buf = &auditBuffer{transaction: tx}
			a.buffers[key] = buf
		}
		a.append(buf, line)
		if section == "Z" {
			raw := strings.Join(buf.lines, "\n")
			if buf.truncated {
				raw += "\n[NTShield: WAF audit transaction truncated]"
			}
			delete(a.buffers, key)
			if ev, ok := ParseWAF(raw, receivedAt); ok {
				return []WAFEvent{ev}
			}
		}
		return nil
	}

	if buf := a.buffers[source]; buf != nil {
		a.append(buf, line)
		return nil
	}
	if ev, ok := ParseWAF(line, receivedAt); ok {
		return []WAFEvent{ev}
	}
	return nil
}

func (a *WAFAccumulator) append(buf *auditBuffer, line string) {
	if buf.truncated {
		return
	}
	needed := len(line) + 1
	if buf.bytes+needed > a.maxBytes {
		remaining := a.maxBytes - buf.bytes
		if remaining > 0 {
			if remaining > len(line) {
				remaining = len(line)
			}
			buf.lines = append(buf.lines, line[:remaining])
			buf.bytes += remaining
		}
		buf.truncated = true
		return
	}
	buf.lines = append(buf.lines, line)
	buf.bytes += needed
}

func ParseWAF(raw string, receivedAt time.Time) (WAFEvent, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return WAFEvent{}, false
	}
	lower := strings.ToLower(trimmed)
	looksWAF := strings.Contains(lower, "modsecurity") ||
		strings.Contains(lower, "mod_security") ||
		strings.Contains(lower, "web application firewall") ||
		strings.Contains(lower, "waf violation") ||
		strings.Contains(lower, "attack_type") ||
		(strings.HasPrefix(trimmed, "{") && (strings.Contains(lower, "ruleid") || strings.Contains(lower, "rule_id"))) ||
		auditBoundaryRE.MatchString(firstLine(trimmed))
	if !looksWAF {
		return WAFEvent{}, false
	}

	ev := WAFEvent{
		Timestamp: receivedAt.UTC(),
		Provider:  "WAF",
		Severity:  2,
		Action:    "detected",
		Raw:       RedactWAFRaw(trimmed),
	}
	if strings.Contains(lower, "modsecurity") || auditBoundaryRE.MatchString(firstLine(trimmed)) {
		ev.Provider = "ModSecurity"
	}

	if strings.HasPrefix(trimmed, "{") {
		parseJSONWAF(trimmed, &ev)
	}
	if m := idRE.FindStringSubmatch(trimmed); m != nil {
		ev.RuleID = m[1]
	}
	if m := msgRE.FindStringSubmatch(trimmed); m != nil {
		ev.Message = unescapeLogValue(m[1])
	}
	if m := severityRE.FindStringSubmatch(trimmed); m != nil {
		ev.Severity = severityNumber(m[1])
	}
	if m := hostnameRE.FindStringSubmatch(trimmed); m != nil {
		ev.Host = unescapeLogValue(m[1])
	}
	if m := uriRE.FindStringSubmatch(trimmed); m != nil {
		ev.URI = unescapeLogValue(m[1])
	}
	if m := uniqueIDRE.FindStringSubmatch(trimmed); m != nil {
		ev.UniqueID = m[1]
	}
	if m := clientRE.FindStringSubmatch(trimmed); m != nil {
		ev.SourceIP, ev.SourcePort = splitHostPortLoose(m[1])
	}
	if ev.URI == "" {
		if m := requestLineRE.FindStringSubmatch(trimmed); m != nil {
			ev.URI = m[1]
		}
	}
	if ev.SourceIP == "" {
		if m := auditARecordRE.FindStringSubmatch(trimmed); m != nil {
			ev.SourceIP = strings.Trim(m[1], "[]")
			ev.SourcePort, _ = strconv.Atoi(m[2])
		}
	}

	if strings.Contains(lower, "access denied") || strings.Contains(lower, "intercepted") ||
		strings.Contains(lower, `"action":"deny"`) || strings.Contains(lower, `"action": "deny"`) ||
		strings.Contains(lower, "blocked") {
		ev.Action = "blocked"
	}
	if ev.Message == "" {
		ev.Message = compactMessage(trimmed, 240)
	}
	if ev.RuleID == "" {
		ev.RuleID = "WAF-UNCLASSIFIED"
	}
	return ev, true
}

func parseJSONWAF(raw string, ev *WAFEvent) {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return
	}
	values := make(map[string][]string)
	walkJSON("", v, values)
	first := func(keys ...string) string {
		for _, key := range keys {
			vals := values[strings.ToLower(key)]
			for _, val := range vals {
				if strings.TrimSpace(val) != "" {
					return val
				}
			}
		}
		return ""
	}
	if s := first("ruleid", "rule_id", "details.ruleid", "details.rule_id", "id"); s != "" {
		ev.RuleID = s
	}
	if s := first("message", "msg", "messages.message", "details.message"); s != "" {
		ev.Message = s
	}
	if s := first("severity", "details.severity"); s != "" {
		ev.Severity = severityNumber(s)
	}
	if s := first("client_ip", "clientip", "source_ip", "src_ip", "transaction.client_ip"); s != "" {
		ev.SourceIP = strings.Trim(s, "[]")
	}
	if s := first("client_port", "source_port", "src_port", "transaction.client_port"); s != "" {
		ev.SourcePort, _ = strconv.Atoi(s)
	}
	if s := first("uri", "request_uri", "transaction.request.uri"); s != "" {
		ev.URI = s
	}
	if s := first("host", "hostname", "transaction.request.headers.host"); s != "" {
		ev.Host = s
	}
	if s := first("unique_id", "uniqueid", "transaction.unique_id", "transaction.id"); s != "" {
		ev.UniqueID = s
	}
	if s := first("action", "disposition"); strings.EqualFold(s, "deny") || strings.EqualFold(s, "block") {
		ev.Action = "blocked"
	}
}

func walkJSON(prefix string, value any, out map[string][]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			path := strings.ToLower(key)
			if prefix != "" {
				path = prefix + "." + path
			}
			walkJSON(path, child, out)
		}
	case []any:
		for _, child := range v {
			walkJSON(prefix, child, out)
		}
	case string:
		out[prefix] = append(out[prefix], v)
		if i := strings.LastIndexByte(prefix, '.'); i >= 0 {
			out[prefix[i+1:]] = append(out[prefix[i+1:]], v)
		}
	case float64:
		s := strconv.FormatFloat(v, 'f', -1, 64)
		out[prefix] = append(out[prefix], s)
		if i := strings.LastIndexByte(prefix, '.'); i >= 0 {
			out[prefix[i+1:]] = append(out[prefix[i+1:]], s)
		}
	case bool:
		s := strconv.FormatBool(v)
		out[prefix] = append(out[prefix], s)
	}
}

func RedactWAFRaw(raw string) string {
	raw = authorizationRE.ReplaceAllString(raw, "$1: [REDACTED]")
	raw = cookieRE.ReplaceAllString(raw, "$1: [REDACTED]")
	raw = jsonSecretRE.ReplaceAllString(raw, `${1}"[REDACTED]"`)
	return raw
}

func severityNumber(s string) int {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(s, "critical"), strings.Contains(s, "emergency"), strings.Contains(s, "alert"):
		return 4
	case strings.Contains(s, "error"), strings.Contains(s, "high"):
		return 3
	case strings.Contains(s, "warn"), strings.Contains(s, "medium"):
		return 2
	case strings.Contains(s, "notice"), strings.Contains(s, "low"):
		return 1
	default:
		if n, err := strconv.Atoi(s); err == nil {
			switch {
			case n <= 2:
				return 4
			case n == 3:
				return 3
			case n == 4:
				return 2
			default:
				return 1
			}
		}
		return 2
	}
}

func splitHostPortLoose(s string) (string, int) {
	s = strings.TrimSpace(strings.Trim(s, "[]"))
	idx := strings.LastIndexByte(s, ':')
	if idx > 0 && strings.Count(s, ":") == 1 {
		if port, err := strconv.Atoi(s[idx+1:]); err == nil {
			return s[:idx], port
		}
	}
	return s, 0
}

func unescapeLogValue(s string) string {
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

func compactMessage(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (e WAFEvent) String() string {
	return fmt.Sprintf("%s rule=%s action=%s src=%s uri=%s msg=%s", e.Provider, e.RuleID, e.Action, e.SourceIP, e.URI, e.Message)
}
