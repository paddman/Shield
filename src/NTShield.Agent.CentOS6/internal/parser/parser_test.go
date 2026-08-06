package parser

import (
	"strings"
	"testing"
	"time"
)

func TestParseRFC3164(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.Local)
	m := ParseSyslog(`<134>Aug  5 11:59:00 web01 sshd[123]: Failed password for root from 10.0.0.8 port 4321 ssh2`, now, "10.0.0.2:514")
	if m.Facility != 16 || m.Severity != 6 {
		t.Fatalf("bad PRI: facility=%d severity=%d", m.Facility, m.Severity)
	}
	if m.Hostname != "web01" || m.AppName != "sshd" || m.ProcessID != "123" {
		t.Fatalf("bad header: %#v", m)
	}
	if m.SourceIP != "10.0.0.2" || !strings.Contains(m.Message, "Failed password") {
		t.Fatalf("bad payload: %#v", m)
	}
}

func TestParseRFC5424(t *testing.T) {
	m := ParseSyslog(`<165>1 2026-08-05T04:00:00Z waf01 modsec 99 ID47 [exampleSDID@32473 iut="3"] blocked request`, time.Now(), "[2001:db8::1]:514")
	if m.Hostname != "waf01" || m.AppName != "modsec" || m.ProcessID != "99" {
		t.Fatalf("bad RFC5424 header: %#v", m)
	}
	if m.Message != "blocked request" || m.SourceIP != "2001:db8::1" {
		t.Fatalf("bad RFC5424 payload: %#v", m)
	}
}

func TestParseModSecurityLine(t *testing.T) {
	raw := `[Wed Aug 05 11:00:00.000000 2026] [:error] [pid 123] [client 203.0.113.8:51515] ModSecurity: Access denied with code 403 (phase 2). [id "942100"] [msg "SQL Injection Attack Detected"] [severity "CRITICAL"] [hostname "example.test"] [uri "/login?id=1"] [unique_id "abc"]`
	ev, ok := ParseWAF(raw, time.Now())
	if !ok {
		t.Fatal("expected WAF event")
	}
	if ev.RuleID != "942100" || ev.Action != "blocked" || ev.Severity != 4 || ev.SourceIP != "203.0.113.8" || ev.SourcePort != 51515 {
		t.Fatalf("bad WAF event: %#v", ev)
	}
}

func TestAuditAccumulatorAndRedaction(t *testing.T) {
	a := NewWAFAccumulator(64 * 1024)
	lines := []string{
		"--abc-A--",
		"[05/Aug/2026:11:00:00 +0700] abc 198.51.100.10 41234 10.0.0.10 443",
		"--abc-B--",
		"POST /login HTTP/1.1",
		"Authorization: Bearer secret-token",
		"Cookie: sid=secret",
		"--abc-H--",
		`Message: Access denied [id "930120"] [msg "OS File Access Attempt"] [severity "CRITICAL"]`,
		"--abc-Z--",
	}
	var got []WAFEvent
	for _, line := range lines {
		got = append(got, a.Feed("audit.log", line, time.Now())...)
	}
	if len(got) != 1 {
		t.Fatalf("expected one event, got %d", len(got))
	}
	if got[0].URI != "/login" || got[0].SourceIP != "198.51.100.10" {
		t.Fatalf("bad audit parse: %#v", got[0])
	}
	if strings.Contains(got[0].Raw, "secret-token") || strings.Contains(got[0].Raw, "sid=secret") {
		t.Fatalf("secrets were not redacted: %s", got[0].Raw)
	}
}
