package loadtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// memURLs parses LOADTEST_MEMORY_URLS (comma-separated enclave /memory URLs).
func memURLs() []string {
	var urls []string
	for _, u := range strings.Split(os.Getenv("LOADTEST_MEMORY_URLS"), ",") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

// sampleMem GETs each /memory URL once and returns a one-line "url usedMB=N"
// summary. usedMB is the enclave's Go-runtime mapped memory; note it is a
// high-water-ish figure (the Go runtime returns memory to the OS lazily), so it
// shows the growth envelope more than instantaneous live use.
func sampleMem(client *http.Client, urls []string) string {
	parts := make([]string, 0, len(urls))
	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			parts = append(parts, fmt.Sprintf("%s=UNREACHABLE(%v)", u, err))
			continue
		}
		var m struct {
			UsedMB uint64 `json:"usedMB"`
			RSSMB  uint64 `json:"rssMB"` // includes wasmtime native memory; the number to watch
		}
		_ = json.NewDecoder(resp.Body).Decode(&m)
		_ = resp.Body.Close()
		parts = append(parts, fmt.Sprintf("%s rssMB=%d usedMB=%d", u, m.RSSMB, m.UsedMB))
	}
	return strings.Join(parts, " | ")
}

// fireOne sends a single workflows.execute and reports the outcome.
func fireOne(client *http.Client, cfg loadConfig) (status int, execID, errMsg string, ackMs float64) {
	req, err := buildExecuteRequest(cfg)
	if err != nil {
		return 0, "", err.Error(), 0
	}
	body, _ := json.Marshal(req)
	s := time.Now()
	httpReq, _ := http.NewRequest(http.MethodPost, cfg.gatewayURL, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/jsonrpc")
	httpReq.Header.Set("Accept", "application/json")
	resp, err := client.Do(httpReq)
	ackMs = float64(time.Since(s).Microseconds()) / 1000
	if err != nil {
		return 0, "", err.Error(), ackMs
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	status = resp.StatusCode
	var out struct {
		Result struct {
			ExecID string `json:"workflow_execution_id"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(rb, &out) == nil {
		execID = out.Result.ExecID
		if out.Error != nil {
			errMsg = string(out.Error)
		}
	}
	return status, execID, errMsg, ackMs
}

// TestRamp_Stepped fires one trigger at a time (round-robin across
// LOADTEST_WORKFLOW_IDS), sampling each enclave's /memory right BEFORE every
// fire, so you can watch the exact per-enclave memory state as executions pile
// up. Unlike TestBurst_Concurrent (all at once), this is a controlled ramp.
//
// Knobs: STEP_COUNT (default = number of IDs), STEP_INTERVAL_SECONDS (default 2;
// small = executions overlap and memory climbs, large = each drains first).
// Requires LOADTEST_MEMORY_URLS to see memory (otherwise it just ramps).
func TestRamp_Stepped(t *testing.T) {
	gw := os.Getenv("LOADTEST_GATEWAY_URL")
	pk := os.Getenv("CRE_LOADTEST_PRIVATE_KEY")
	if gw == "" || pk == "" {
		t.Skip("set LOADTEST_GATEWAY_URL and CRE_LOADTEST_PRIVATE_KEY")
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(pk, "0x"))
	if err != nil {
		t.Fatalf("bad key: %v", err)
	}

	var ids []string
	for _, s := range strings.Split(os.Getenv("LOADTEST_WORKFLOW_IDS"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			ids = append(ids, s)
		}
	}
	if len(ids) == 0 {
		if id := os.Getenv("LOADTEST_WORKFLOW_ID"); id != "" {
			ids = []string{id}
		}
	}
	if len(ids) == 0 {
		t.Fatal("set LOADTEST_WORKFLOW_IDS (comma-separated) or LOADTEST_WORKFLOW_ID")
	}

	urls := memURLs()
	if len(urls) == 0 {
		t.Log("warning: LOADTEST_MEMORY_URLS unset — ramping without memory sampling")
	}

	steps := envIntOr(t, "STEP_COUNT", len(ids))
	gap := time.Duration(envIntOr(t, "STEP_INTERVAL_SECONDS", 2)) * time.Second

	cfg := loadConfig{
		gatewayURL: gw,
		privKey:    key,
		owner:      os.Getenv("LOADTEST_WORKFLOW_OWNER"),
		name:       envOr("LOADTEST_WORKFLOW_NAME", "cn_confidential_workflows_load_a"),
		input:      envOr("LOADTEST_INPUT", `{"n":1}`),
	}
	client := &http.Client{Timeout: 120 * time.Second}

	t.Logf("stepped ramp: %d fires, 1 per workflow (round-robin over %d IDs), %v between fires, sampling %d enclave(s)",
		steps, len(ids), gap, len(urls))

	var execIDs []string
	for i := 0; i < steps; i++ {
		if len(urls) > 0 {
			t.Logf("STEP %2d  PRE-FIRE  %s", i, sampleMem(client, urls))
		}
		ci := cfg
		ci.id = ids[i%len(ids)]
		ci.name = "" // ID takes precedence in the selector
		status, execID, errMsg, ackMs := fireOne(client, ci)
		if execID != "" {
			execIDs = append(execIDs, execID)
		}
		t.Logf("STEP %2d  FIRE      wf=%s http=%d ack=%.0fms exec=%s %s",
			i, ci.id[:10], status, ackMs, execID, errMsg)
		if i < steps-1 {
			time.Sleep(gap)
		}
	}
	if len(urls) > 0 {
		t.Logf("POST-RUN  %s", sampleMem(client, urls))
	}
	t.Logf("accepted exec IDs (%d): %s", len(execIDs), strings.Join(execIDs, ","))
}
