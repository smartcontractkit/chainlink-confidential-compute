package server

import "testing"

func TestParseVmRSSBytes(t *testing.T) {
	const status = `Name:	go-enclave
Umask:	0022
State:	R (running)
VmPeak:	 2100000 kB
VmSize:	 2000000 kB
VmRSS:	 1234560 kB
RssAnon:	 1200000 kB
Threads:	42
`
	if got, want := parseVmRSSBytes([]byte(status)), uint64(1234560)*1024; got != want {
		t.Fatalf("parseVmRSSBytes = %d, want %d", got, want)
	}

	cases := map[string][]byte{
		"missing line": []byte("Name:\tx\nVmSize:\t100 kB\n"),
		"empty input":  []byte(""),
		"malformed":    []byte("VmRSS:\tnotanumber kB\n"),
		"no value":     []byte("VmRSS:\n"),
	}
	for name, in := range cases {
		if got := parseVmRSSBytes(in); got != 0 {
			t.Errorf("%s: parseVmRSSBytes = %d, want 0", name, got)
		}
	}
}
