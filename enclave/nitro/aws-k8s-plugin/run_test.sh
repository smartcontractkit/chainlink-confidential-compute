#!/usr/bin/env bash
# Tests for run.sh's enclave supervision, without a real Nitro host.
# Stubs nitro-cli, curl and sleep on PATH and asserts:
#   1. a wedged enclave (probe fails) makes run.sh exit so k8s restarts it,
#   2. a healthy enclave (probe 200) keeps run.sh running,
#   3. a stale enclave is terminated by id (never --all) before re-launch.
# Requires: bash, jq.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
RUN_SH="$HERE/run.sh"
FAILURES=0

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
# Resolve the real sleep now, before the stub dir goes on PATH, so the stub can
# call it without re-resolving to itself.
REAL_SLEEP="$(command -v sleep)"

# make_stubs <workdir> <initial-enclave-id-or-empty> <http-code>
make_stubs() {
  local work="$1" init_id="$2" http_code="$3"
  local bin="$work/bin"; mkdir -p "$bin"
  echo -n "$init_id"   > "$work/state"
  echo -n "$http_code" > "$work/code"
  : > "$work/terminate.log"

  cat > "$bin/curl" <<EOF
#!/usr/bin/env bash
cat "$work/code"
EOF
  cat > "$bin/sleep" <<EOF
#!/usr/bin/env bash
exec "$REAL_SLEEP" 0.05
EOF
  cat > "$bin/nitro-cli" <<EOF
#!/usr/bin/env bash
case "\$1" in
  run-enclave)       echo -n "i-launched" > "$work/state" ;;
  describe-enclaves) id=\$(cat "$work/state"); if [ -n "\$id" ]; then echo "[{\"EnclaveID\":\"\$id\"}]"; else echo "[]"; fi ;;
  terminate-enclave) echo "\$*" >> "$work/terminate.log"; echo -n "" > "$work/state" ;;
esac
EOF
  chmod +x "$bin"/*
}

# run_bounded <secs> <workdir> ... env=VAL ...  -> sets RC and OUT
run_bounded() {
  local secs="$1" work="$2"; shift 2
  OUT="$work/out"
  env PATH="$work/bin:$PATH" "$@" bash "$RUN_SH" > "$OUT" 2>&1 &
  local pid=$!
  ( command sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) & local killer=$!
  wait "$pid" 2>/dev/null; RC=$?
  kill "$killer" 2>/dev/null; wait "$killer" 2>/dev/null || true
}

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); }

# 1. Wedged: probe returns 500 -> run.sh must exit (not be killed).
w=$(mktemp -d); make_stubs "$w" "" 500
run_bounded 10 "$w" HEALTH_FAIL_THRESHOLD=2
if [ "$RC" != "143" ] && grep -q "wedged" "$OUT"; then pass "wedged enclave -> run.sh exits"; else fail "wedged enclave -> run.sh exits (rc=$RC)"; fi
rm -rf "$w"

# 2. Healthy: probe returns 200 -> run.sh keeps running (gets killed by us).
w=$(mktemp -d); make_stubs "$w" "" 200
run_bounded 3 "$w" HEALTH_FAIL_THRESHOLD=2
if [ "$RC" = "143" ]; then pass "healthy enclave -> run.sh stays up"; else fail "healthy enclave -> run.sh stays up (rc=$RC)"; fi
rm -rf "$w"

# 3. Stale enclave present at start -> terminated by its id, never --all.
w=$(mktemp -d); make_stubs "$w" "i-stale-123" 500
run_bounded 10 "$w" HEALTH_FAIL_THRESHOLD=1
if grep -q -- "--enclave-id i-stale-123" "$w/terminate.log" && ! grep -q -- "--all" "$w/terminate.log"; then
  pass "stale enclave terminated by id (not --all)"
else
  fail "stale enclave terminated by id (not --all); log: $(cat "$w/terminate.log")"
fi
rm -rf "$w"

echo "----"
[ "$FAILURES" -eq 0 ] && { echo "all tests passed"; exit 0; } || { echo "$FAILURES test(s) failed"; exit 1; }
