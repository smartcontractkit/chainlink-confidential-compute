package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/teeattestation/nitro"
	"github.com/smartcontractkit/confidential-compute/types"
	"gopkg.in/yaml.v3"
)

const defaultCLDRepo = "smartcontractkit/chainlink-deployments"

// cldEnclave is a single enclave decoded from a chainlink-deployments pipeline
// changeset, with the trusted PCR measurements proposed for it.
type cldEnclave struct {
	URL string
	// Measurements is the set of trusted measurements proposed in the PR. Each
	// entry is the raw JSON ({"pcr0":...,"pcr1":...,"pcr2":...}) that
	// nitro.ValidateAttestation unmarshals directly.
	Measurements [][]byte
	SourceFiles  []string
}

// ghPRView is the subset of `gh pr view --json files,headRefName` we consume.
type ghPRView struct {
	HeadRefName string `json:"headRefName"`
	Files       []struct {
		Path string `json:"path"`
	} `json:"files"`
}

// runValidateCLDPR fetches the enclave config from a chainlink-deployments PR
// and checks that the proposed measurements can validate the live attested
// /publicKeys response from each enclave, using the same validation the client
// pool uses.
func runValidateCLDPR(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Error: validate-cld-pr requires a PR URL or number\n")
		printUsage()
		os.Exit(1)
	}

	prArg := args[0]
	repo := defaultCLDRepo
	apiKey := os.Getenv("ENCLAVE_API_KEY")

	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--repo":
			if i+1 >= len(rest) {
				fmt.Fprintf(os.Stderr, "Error: --repo requires a value\n")
				os.Exit(1)
			}
			repo = rest[i+1]
			i++
		case "--api-key":
			if i+1 >= len(rest) {
				fmt.Fprintf(os.Stderr, "Error: --api-key requires a value\n")
				os.Exit(1)
			}
			apiKey = rest[i+1]
			i++
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown flag %q\n", rest[i])
			os.Exit(1)
		}
	}

	if apiKey == "" {
		fmt.Fprintf(os.Stderr, "Error: no API key provided. Pass --api-key <key> or set ENCLAVE_API_KEY\n")
		os.Exit(1)
	}

	prNum, err := parsePRNumber(prArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Inspecting %s PR #%s...\n", repo, prNum)
	view, err := fetchPRView(repo, prNum)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching PR: %v\n", err)
		os.Exit(1)
	}

	enclaves, err := collectEnclaves(repo, view)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if len(enclaves) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no enclaves with trusted measurements found in PR\n")
		os.Exit(1)
	}

	fmt.Printf("Found %d enclave(s) in PR:\n\n", len(enclaves))

	httpClient := &http.Client{Timeout: 15 * time.Second}
	failures := 0

	for _, e := range enclaves {
		fmt.Printf("Enclave: %s\n", e.URL)
		fmt.Println("====================")
		fmt.Printf("  Defined in: %s\n", strings.Join(e.SourceFiles, ", "))
		fmt.Printf("  Proposed measurements: %d\n", len(e.Measurements))
		for i, m := range e.Measurements {
			fmt.Printf("    [%d] %s\n", i+1, summarizePCRs(m))
		}

		if !validateEnclave(httpClient, e, apiKey) {
			failures++
		}
		fmt.Println()
	}

	fmt.Println("======================================")
	if failures == 0 {
		fmt.Printf("PASS: all %d enclave(s) validated against the PR's measurements\n", len(enclaves))
		return
	}
	fmt.Printf("FAIL: %d of %d enclave(s) could not be validated\n", failures, len(enclaves))
	os.Exit(1)
}

// validateEnclave fetches the live attested /publicKeys response and checks it
// against each proposed measurement. Returns true if at least one validates.
func validateEnclave(httpClient *http.Client, e cldEnclave, apiKey string) bool {
	resp, err := fetchPublicKeys(httpClient, e.URL, apiKey)
	if err != nil {
		fmt.Printf("  RESULT: FAIL - could not fetch attested response: %v\n", err)
		return false
	}

	userData := resp.PublicKeyHash()
	matched := -1
	var errs []string
	for i, m := range e.Measurements {
		if err := nitro.ValidateAttestation(resp.Attestation, userData[:], m); err != nil {
			errs = append(errs, fmt.Sprintf("    [%d] %s: %v", i+1, summarizePCRs(m), err))
			continue
		}
		matched = i
		break
	}

	if matched >= 0 {
		fmt.Printf("  RESULT: PASS - measurement [%d] validates the attested response\n", matched+1)
		return true
	}

	fmt.Printf("  RESULT: FAIL - no proposed measurement validates the attested response\n")
	for _, e := range errs {
		fmt.Println(e)
	}
	return false
}

// fetchPublicKeys performs the same GET /publicKeys call the pool makes,
// authenticating with the x-api-key header, and decodes the response.
func fetchPublicKeys(httpClient *http.Client, enclaveURL, apiKey string) (*types.PublicKeyResponse, error) {
	endpoint := publicKeysEndpoint(enclaveURL)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", apiKey)

	httpResp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", httpResp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out types.PublicKeyResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(out.Attestation) == 0 {
		return nil, fmt.Errorf("response contained no attestation")
	}
	return &out, nil
}

// publicKeysEndpoint normalizes an enclave URL to its /publicKeys endpoint,
// matching how the pool appends types.PublicKeyPath.
func publicKeysEndpoint(enclaveURL string) string {
	u := strings.TrimRight(enclaveURL, "/")
	u = strings.TrimSuffix(u, types.PublicKeyPath)
	return u + types.PublicKeyPath
}

var prNumberRe = regexp.MustCompile(`^\d+$`)

func parsePRNumber(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if prNumberRe.MatchString(arg) {
		return arg, nil
	}
	// Match .../pull/<num> optionally followed by /, #, or query.
	re := regexp.MustCompile(`/pull/(\d+)`)
	if m := re.FindStringSubmatch(arg); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("could not parse PR number from %q", arg)
}

func fetchPRView(repo, prNum string) (*ghPRView, error) {
	out, err := runGH("pr", "view", prNum, "--repo", repo, "--json", "files,headRefName")
	if err != nil {
		return nil, err
	}
	var view ghPRView
	if err := json.Unmarshal(out, &view); err != nil {
		return nil, fmt.Errorf("decode gh output: %w", err)
	}
	if view.HeadRefName == "" {
		return nil, fmt.Errorf("PR has no head ref")
	}
	return &view, nil
}

// collectEnclaves fetches each changed YAML file in the PR and extracts the
// enclaves, merging measurements for enclaves that appear in more than one file.
func collectEnclaves(repo string, view *ghPRView) ([]cldEnclave, error) {
	byURL := map[string]*cldEnclave{}
	seenMeasurement := map[string]map[string]bool{}

	for _, f := range view.Files {
		if !strings.HasSuffix(f.Path, ".yaml") && !strings.HasSuffix(f.Path, ".yml") {
			continue
		}
		content, err := fetchFileRaw(repo, f.Path, view.HeadRefName)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", f.Path, err)
		}
		found, err := extractEnclavesFromYAML(content)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.Path, err)
		}
		for _, e := range found {
			existing, ok := byURL[e.URL]
			if !ok {
				existing = &cldEnclave{URL: e.URL}
				byURL[e.URL] = existing
				seenMeasurement[e.URL] = map[string]bool{}
			}
			if !contains(existing.SourceFiles, f.Path) {
				existing.SourceFiles = append(existing.SourceFiles, f.Path)
			}
			for _, m := range e.Measurements {
				key := string(m)
				if seenMeasurement[e.URL][key] {
					continue
				}
				seenMeasurement[e.URL][key] = true
				existing.Measurements = append(existing.Measurements, m)
			}
		}
	}

	var result []cldEnclave
	for _, e := range byURL {
		if len(e.Measurements) == 0 {
			continue
		}
		result = append(result, *e)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].URL < result[j].URL })
	return result, nil
}

// extractEnclavesFromYAML walks the decoded YAML looking for any "Enclaves"
// listValue block (the on-chain config map encoding) regardless of which
// changeset wraps it, and decodes each enclave's URL and trusted measurements.
func extractEnclavesFromYAML(data []byte) ([]cldEnclave, error) {
	var root interface{}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var out []cldEnclave
	walkForEnclaves(root, &out)
	return out, nil
}

func walkForEnclaves(node interface{}, out *[]cldEnclave) {
	switch n := node.(type) {
	case map[string]interface{}:
		if enclavesField, ok := n["Enclaves"].(map[string]interface{}); ok {
			if enclaves := decodeEnclavesField(enclavesField); len(enclaves) > 0 {
				*out = append(*out, enclaves...)
			}
		}
		for _, v := range n {
			walkForEnclaves(v, out)
		}
	case []interface{}:
		for _, v := range n {
			walkForEnclaves(v, out)
		}
	}
}

func decodeEnclavesField(enclavesField map[string]interface{}) []cldEnclave {
	listValue, ok := enclavesField["listValue"].(map[string]interface{})
	if !ok {
		return nil
	}
	fields, ok := listValue["fields"].([]interface{})
	if !ok {
		return nil
	}

	var out []cldEnclave
	for _, entry := range fields {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		mapValue, ok := entryMap["mapValue"].(map[string]interface{})
		if !ok {
			continue
		}
		enclaveFields, ok := mapValue["fields"].(map[string]interface{})
		if !ok {
			continue
		}

		var e cldEnclave
		if urlField, ok := enclaveFields["EnclaveURL"].(map[string]interface{}); ok {
			if url, ok := urlField["stringValue"].(string); ok {
				e.URL = url
			}
		}
		if e.URL == "" {
			continue
		}
		e.Measurements = decodeTrustedValues(enclaveFields["TrustedValues"])
		out = append(out, e)
	}
	return out
}

// decodeTrustedValues handles both encodings of TrustedValues: a single
// bytesValue, or a listValue of bytesValues. Each decoded value is the raw
// PCR JSON that nitro.ValidateAttestation consumes.
func decodeTrustedValues(field interface{}) [][]byte {
	trusted, ok := field.(map[string]interface{})
	if !ok {
		return nil
	}

	var out [][]byte
	add := func(b64 string) {
		if b64 == "" {
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return
		}
		out = append(out, decoded)
	}

	if listValue, ok := trusted["listValue"].(map[string]interface{}); ok {
		if fields, ok := listValue["fields"].([]interface{}); ok {
			for _, entry := range fields {
				if entryMap, ok := entry.(map[string]interface{}); ok {
					if b64, ok := entryMap["bytesValue"].(string); ok {
						add(b64)
					}
				}
			}
		}
	}
	if b64, ok := trusted["bytesValue"].(string); ok {
		add(b64)
	}
	return out
}

// summarizePCRs renders a short, readable description of a PCR measurement JSON.
func summarizePCRs(raw []byte) string {
	var pcrs nitro.PCRs
	if err := json.Unmarshal(raw, &pcrs); err != nil {
		return fmt.Sprintf("(unparseable: %s)", string(raw))
	}
	short := func(b []byte) string {
		s := fmt.Sprintf("%x", b)
		if len(s) > 12 {
			return s[:12] + "..."
		}
		return s
	}
	return fmt.Sprintf("PCR0=%s PCR1=%s PCR2=%s", short(pcrs.PCR0), short(pcrs.PCR1), short(pcrs.PCR2))
}

func fetchFileRaw(repo, path, ref string) ([]byte, error) {
	return runGH("api",
		"-H", "Accept: application/vnd.github.raw",
		fmt.Sprintf("repos/%s/contents/%s?ref=%s", repo, path, ref),
	)
}

func runGH(args ...string) ([]byte, error) {
	cmd := exec.Command("gh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
