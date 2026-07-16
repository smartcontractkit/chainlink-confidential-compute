package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/teeattestation/nitro"
)

// pcrSetJSON renders a PCRSet as the trusted-measurement JSON that
// nitro.ValidateAndParse consumes (hex-string pcr0/pcr1/pcr2 fields).
func pcrSetJSON(m PCRSet) []byte {
	b, _ := json.Marshal(map[string]string{"pcr0": m.PCR0, "pcr1": m.PCR1, "pcr2": m.PCR2})
	return b
}

// runCheckProd fetches the live attested /publicKeys response from each configured
// enclave and reports which known measurement (if any) validates it.
func runCheckProd(args []string) {
	apiKey := os.Getenv("ENCLAVE_API_KEY")
	if apiKey == "" && len(args) > 0 {
		apiKey = args[0]
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: provide API key via ENCLAVE_API_KEY or as the first argument")
		printUsage()
		os.Exit(1)
	}

	client := &http.Client{Timeout: 15 * time.Second}

	for _, enclave := range config.Enclaves {
		url := enclave.EnclaveURL
		fmt.Printf("Enclave: %s\n", url)
		fmt.Println("====================")

		resp, err := fetchPublicKeys(client, url, apiKey)
		if err != nil {
			fmt.Printf("  ERROR fetching /publicKeys: %v\n\n", err)
			continue
		}

		userData := resp.PublicKeyHash()

		matched := ""
		var doc *nitro.Document
		for i, m := range validMeasurements {
			d, err := nitro.ValidateAndParse(resp.Attestation, userData[:], pcrSetJSON(m))
			if err == nil {
				matched = fmt.Sprintf("measurement #%d", i+1)
				doc = d
				break
			}
		}

		if doc != nil {
			fmt.Printf("  Running: %s (attestation validates)\n", matched)
			fmt.Printf("    PCR0: %s\n", hex.EncodeToString(doc.PCRs[0]))
			fmt.Printf("    PCR1: %s\n", hex.EncodeToString(doc.PCRs[1]))
			fmt.Printf("    PCR2: %s\n", hex.EncodeToString(doc.PCRs[2]))
		} else {
			fmt.Printf("  Running: UNKNOWN - no listed measurement validates the live attestation\n")
			// Try each measurement anyway to surface why none matched.
			for i, m := range validMeasurements {
				_, err := nitro.ValidateAndParse(resp.Attestation, userData[:], pcrSetJSON(m))
				fmt.Printf("    vs measurement #%d: %v\n", i+1, err)
			}
		}
		fmt.Println()
	}
}
