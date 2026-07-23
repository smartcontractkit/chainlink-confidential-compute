package loadtest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// startMemoryPoller samples the enclave GET /memory endpoints listed in
// LOADTEST_MEMORY_URLS (comma-separated) every 200ms and logs usedMB, so the
// enclave's memory can be watched through a burst. No-op if the env is unset.
// The enclave /memory is on the host behind the VPC-internal griddle URL, so
// point this at a reachable address (e.g. a kubectl port-forward to the
// enclave-workflows host-container). Returns a stop function.
func startMemoryPoller(t *testing.T) func() {
	raw := os.Getenv("LOADTEST_MEMORY_URLS")
	if raw == "" {
		return func() {}
	}
	var urls []string
	for _, u := range strings.Split(raw, ",") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()
	client := &http.Client{Timeout: 2 * time.Second}
	for _, u := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			tick := time.NewTicker(200 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					resp, err := client.Get(u)
					if err != nil {
						continue
					}
					var m struct {
						UsedMB uint64 `json:"usedMB"`
					}
					_ = json.NewDecoder(resp.Body).Decode(&m)
					_ = resp.Body.Close()
					t.Logf("MEM t=%5.1fs %s usedMB=%d", time.Since(start).Seconds(), u, m.UsedMB)
				}
			}
		}(u)
	}
	return func() { close(stop); wg.Wait() }
}

// TestBurst_Concurrent fires BURST_N (default 10) requests as simultaneously as
// possible and records each request's ACK latency + gateway-returned execution
// ID + HTTP status. It prints the send-window start (UTC) and the exec IDs so
// phase 2 can compute true completion latency/throughput from
// `cre execution list` (Started/Finished per exec) — the gateway ACK is async
// (returns ACCEPTED, not the enclave result), so send->done isn't observable
// client-side. Diagnostic; skips unless the gateway URL + trigger key are set.
func TestBurst_Concurrent(t *testing.T) {
	gw := os.Getenv("LOADTEST_GATEWAY_URL")
	pk := os.Getenv("CRE_LOADTEST_PRIVATE_KEY")
	if gw == "" || pk == "" {
		t.Skip("set LOADTEST_GATEWAY_URL and CRE_LOADTEST_PRIVATE_KEY")
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(pk, "0x"))
	if err != nil {
		t.Fatalf("bad key: %v", err)
	}
	n := 10
	if v := os.Getenv("BURST_N"); v != "" {
		if parsed, e := strconv.Atoi(v); e == nil {
			n = parsed
		}
	}
	cfg := loadConfig{
		gatewayURL: gw,
		privKey:    key,
		owner:      os.Getenv("LOADTEST_WORKFLOW_OWNER"),
		name:       envOr("LOADTEST_WORKFLOW_NAME", "cn_confidential_workflows_load_a"),
		id:         os.Getenv("LOADTEST_WORKFLOW_ID"),
		input:      envOr("LOADTEST_INPUT", `{"n":1}`),
	}

	type res struct {
		idx    int
		status int
		ackMs  float64
		execID string
		errMsg string
	}
	results := make([]res, n)
	client := &http.Client{Timeout: 120 * time.Second}

	// Round-robin across a list of workflow IDs (LOADTEST_WORKFLOW_IDS, comma-
	// separated) so each request hits a different workflow's rate-limit bucket.
	// Falls back to the single LOADTEST_WORKFLOW_ID.
	var ids []string
	if v := os.Getenv("LOADTEST_WORKFLOW_IDS"); v != "" {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				ids = append(ids, s)
			}
		}
	} else if cfg.id != "" {
		ids = []string{cfg.id}
	}
	if len(ids) == 0 {
		t.Fatal("set LOADTEST_WORKFLOW_IDS (comma-separated) or LOADTEST_WORKFLOW_ID")
	}
	t.Logf("rotating across %d workflow IDs", len(ids))

	// Optionally watch enclave memory through the burst + execution window.
	memPollSecs := envIntOr(t, "LOADTEST_MEMORY_POLL_SECONDS", 0)
	stopMem := startMemoryPoller(t)
	defer stopMem()

	// Pre-sign all requests so JWT signing time is not counted in the burst.
	bodies := make([][]byte, n)
	target := make([]string, n)
	for i := 0; i < n; i++ {
		ci := cfg
		ci.id = ids[i%len(ids)]
		ci.name = "" // ID takes precedence in the selector
		target[i] = ci.id
		req, err := buildExecuteRequest(ci)
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		bodies[i], _ = json.Marshal(req)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all goroutines at once
			s := time.Now()
			httpReq, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, cfg.gatewayURL, bytes.NewReader(bodies[i]))
			httpReq.Header.Set("Content-Type", "application/jsonrpc")
			httpReq.Header.Set("Accept", "application/json")
			resp, err := client.Do(httpReq)
			r := res{idx: i, ackMs: float64(time.Since(s).Microseconds()) / 1000}
			if err != nil {
				r.errMsg = err.Error()
				results[i] = r
				return
			}
			defer resp.Body.Close()
			rb, _ := io.ReadAll(resp.Body)
			r.status = resp.StatusCode
			var out struct {
				Result struct {
					ExecID string `json:"workflow_execution_id"`
					Status string `json:"status"`
				} `json:"result"`
				Error json.RawMessage `json:"error"`
			}
			if json.Unmarshal(rb, &out) == nil {
				r.execID = out.Result.ExecID
				if out.Error != nil {
					r.errMsg = string(out.Error)
				}
			}
			results[i] = r
		}(i)
	}
	burstStart := time.Now()
	close(start)
	wg.Wait()
	elapsed := time.Since(burstStart)

	var acks []float64
	ok := 0
	t.Logf("burst: %d concurrent requests; all ACKs returned in %s", n, elapsed.Round(time.Millisecond))
	t.Logf("SEND WINDOW START (UTC): %s   (filter cre execution list on Started >= this)", burstStart.UTC().Format(time.RFC3339Nano))
	for _, r := range results {
		t.Logf("  [%2d] wf=%s http=%d ack=%.0fms exec=%s %s", r.idx, target[r.idx][:10], r.status, r.ackMs, r.execID, r.errMsg)
		if r.status == 200 && r.errMsg == "" {
			ok++
			acks = append(acks, r.ackMs)
		}
	}
	sort.Float64s(acks)
	if len(acks) > 0 {
		sum := 0.0
		for _, a := range acks {
			sum += a
		}
		t.Logf("ACK: accepted=%d/%d  ack_ms avg=%.0f min=%.0f p50=%.0f max=%.0f",
			ok, n, sum/float64(len(acks)), acks[0], acks[len(acks)/2], acks[len(acks)-1])
	}
	var execIDs []string
	for _, r := range results {
		if r.execID != "" {
			execIDs = append(execIDs, r.execID)
		}
	}
	t.Logf("exec IDs (gateway-returned): %s", strings.Join(execIDs, ","))

	// Executions run asynchronously after the ACK; keep sampling /memory through
	// that window if memory polling is enabled.
	if memPollSecs > 0 {
		t.Logf("holding %ds for /memory sampling through execution", memPollSecs)
		time.Sleep(time.Duration(memPollSecs) * time.Second)
	}
}
