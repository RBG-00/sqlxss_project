#!/usr/bin/env bash
# run_tests.sh — integration script for test_server + scanner
# Usage: chmod +x run_tests.sh && ./run_tests.sh

set -euo pipefail
SLEEP_SHORT=1
SLEEP_LONG=2

cleanup() {
  if [ -n "${TS_PID-}" ]; then
    echo "Stopping test_server (pid ${TS_PID})..."
    kill "${TS_PID}" 2>/dev/null || true
    wait "${TS_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

PY=python3

echo "Starting test_server in background..."
# Start test_server.py (must exist in repo root)
$PY test_server.py >/tmp/test_server.log 2>&1 &
TS_PID=$!
sleep $SLEEP_SHORT

# wait up to N seconds for server to bind (simple check)
echo "Waiting for test_server to start (checking / )..."
for i in $(seq 1 10); do
  if curl -sSf --max-time 1 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    echo "test_server is up (after ${i} attempts)."
    break
  fi
  sleep 0.5
  if [ "$i" -eq 10 ]; then
    echo "ERROR: test_server did not start. See /tmp/test_server.log"
    tail -n 100 /tmp/test_server.log || true
    exit 2
  fi
done

# Clean previous report if any
if [ -f report.json ]; then
  rm -f report.json
fi

echo
echo "Running scanner integration checks against test_server..."
# 1) XSS endpoint (reflection) — should be auto-verified by scanner
$PY scanner.py -u "http://127.0.0.1:8080/vuln/xss?q=test" --auto-verify --timeout 8 --len-threshold 0.2 --verbose || true
sleep $SLEEP_SHORT

# 2) SQL endpoint (boolean/time) — should be auto-verified by scanner
$PY scanner.py -u "http://127.0.0.1:8080/vuln/sql?q=test" --auto-verify --timeout 12 --len-threshold 0.2 --verbose || true
sleep $SLEEP_SHORT

# 3) Login POST (form) endpoint — exercise POST flow and JSON form handling
$PY scanner.py -u "http://127.0.0.1:8080/rest/user/login" -m POST \
  --postdata "email=foo&password=1' OR '1'='1" \
  --headers "Content-Type: application/x-www-form-urlencoded|Accept: application/json" \
  --auto-verify --timeout 12 --verbose || true

sleep $SLEEP_SHORT
echo
echo "Parsing report.json for auto-verified findings..."

if [ ! -f report.json ]; then
  echo "ERROR: report.json not produced."
  # show server log for debugging
  echo "---- /tmp/test_server.log (tail) ----"
  tail -n 200 /tmp/test_server.log || true
  exit 3
fi

# Use Python to inspect report.json robustly
$PY - <<'PYCODE'
import json,sys
try:
    j=json.load(open("report.json", "r", encoding="utf-8"))
except Exception as e:
    print("ERROR: cannot read report.json:", e)
    sys.exit(4)

findings = j.get("findings", [])
auto_count = sum(1 for f in findings if f.get("auto_verified") or f.get("verify",{}).get("verified"))
total = len(findings)
print(f"Total findings: {total}")
print(f"Auto-verified findings: {auto_count}")
# Print short summary of up to 10 top findings
top = sorted(findings, key=lambda x: x.get("score",0), reverse=True)[:10]
for f in top:
    print(f"- {f.get('status','?').upper()} | {f.get('vuln_type')} | {f.get('injected_param')} | score={f.get('score')} | auto_verified={f.get('auto_verified')}")
if auto_count > 0:
    sys.exit(0)
else:
    sys.exit(5)
PYCODE

RC=$?
if [ "$RC" -eq 0 ]; then
  echo "Integration check PASSED (at least one auto-verified finding)."
else
  echo "Integration check FAILED (no auto-verified findings)."
fi

# Allow cleanup via trap
exit $RC
