package collector

import "testing"

func TestDecodeProcIPv4(t *testing.T) {
	ip, port, err := decodeProcEndpoint("0100007F:1F90", false)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "127.0.0.1" || port != 8080 {
		t.Fatalf("got %s:%d", ip, port)
	}
}

func TestDecodeProcIPv6(t *testing.T) {
	ip, port, err := decodeProcEndpoint("00000000000000000000000001000000:01BB", true)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "::1" || port != 443 {
		t.Fatalf("got [%s]:%d", ip, port)
	}
}

func TestTCPStateMapping(t *testing.T) {
	cases := map[string]int{"01": 5, "0A": 2, "06": 11, "08": 8}
	for input, want := range cases {
		got, ok := mapLinuxTCPState(input)
		if !ok || got != want {
			t.Fatalf("state %s got=%d ok=%v want=%d", input, got, ok, want)
		}
	}
}
