package nitro

import "testing"

func TestValidateClockSource(t *testing.T) {
	tests := []struct {
		name         string
		architecture string
		source       string
		wantError    bool
	}{
		{name: "x86 KVM clock", architecture: "amd64", source: "kvm-clock"},
		{name: "ARM architected counter", architecture: "arm64", source: "arch_sys_counter"},
		{name: "x86 rejects ARM clock", architecture: "amd64", source: "arch_sys_counter", wantError: true},
		{name: "ARM rejects x86 clock", architecture: "arm64", source: "kvm-clock", wantError: true},
		{name: "x86 rejects TSC", architecture: "amd64", source: "tsc", wantError: true},
		{name: "ARM rejects fallback clock", architecture: "arm64", source: "jiffies", wantError: true},
		{name: "empty clock", architecture: "arm64", wantError: true},
		{name: "read failure", architecture: "arm64", source: "error reading clock source: permission denied", wantError: true},
		{name: "unsupported architecture", architecture: "386", source: "kvm-clock", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClockSource(tt.architecture, tt.source)
			if (err != nil) != tt.wantError {
				t.Fatalf("validateClockSource(%q, %q) = %v, wantError %t", tt.architecture, tt.source, err, tt.wantError)
			}
		})
	}
}
