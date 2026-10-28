#!/usr/bin/env bash
# End-to-end smoke test: runs oxtrace against a fake LLM API over local TLS and checks the
# exported metrics. Needs root (or CAP_BPF + CAP_PERFMON), python3, curl and openssl.
#
#   sudo scripts/e2e.sh [path/to/oxtrace]
set -euo pipefail

bin=${1:-target/release/oxtrace}
port=18443
metrics=127.0.0.1:19464
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
python3 "$(dirname "$0")/fake_llm.py" "$work/cert.pem" "$work/key.pem" "$port" &
"$bin" --metrics-addr "$metrics" --idle-ms 500 >"$work/stdout" 2>"$work/stderr" &

for _ in $(seq 50); do
  curl -sf "http://$metrics/metrics" >/dev/null && break
  sleep 0.2
done

url=https://localhost:$port
# curl drives SSL_write / SSL_read.
curl -sk "$url/v1/messages" -H 'content-type: application/json' -d '{}' >/dev/null
curl -skN "$url/v1/messages?stream=true" -d '{"stream":true}' >/dev/null
# CPython drives SSL_write_ex / SSL_read_ex.
python3 - "$url" <<'PY'
import ssl, sys, urllib.request
req = urllib.request.Request(sys.argv[1] + "/v1/chat/completions", data=b"{}")
urllib.request.urlopen(req, context=ssl._create_unverified_context()).read()
PY

sleep 1.5
curl -s "http://$metrics/metrics" >"$work/metrics"

fail=0
expect() {
  if grep -qxF "$1" "$work/metrics"; then
    echo "ok    $1"
  else
    echo "FAIL  $1"
    fail=1
  fi
}
host="localhost:$port"
expect "oxtrace_llm_tokens_total{comm=\"curl\",host=\"$host\",kind=\"input\"} 35"
expect "oxtrace_llm_tokens_total{comm=\"curl\",host=\"$host\",kind=\"output\"} 196"
expect "oxtrace_llm_tokens_total{comm=\"python3\",host=\"$host\",kind=\"input\"} 12"
expect "oxtrace_llm_tokens_total{comm=\"python3\",host=\"$host\",kind=\"output\"} 7"
expect "oxtrace_http_requests_total{comm=\"curl\",host=\"$host\",method=\"POST\",path=\"/v1/messages\",status=\"200\"} 2"
expect "oxtrace_http_requests_total{comm=\"python3\",host=\"$host\",method=\"POST\",path=\"/v1/chat/completions\",status=\"200\"} 1"

echo "--- oxtrace output"
cat "$work/stdout" "$work/stderr"
if [ "$fail" -ne 0 ]; then
  echo "--- metrics"
  grep -E '^oxtrace_(llm|http_requests)' "$work/metrics" || true
fi
exit "$fail"
