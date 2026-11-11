#!/usr/bin/env bash
# Real-engine test: builds the image with install.sh, runs the installed
# wrapper in real containers, and then re-runs each step's container with the
# very same flags but a probe inside, to see what that step can actually
# reach: the code, the database, the reports, the network.
#
#   tests/docker_e2e.sh [-v]
#
# Needs a working Docker (or CVESCAN_ENGINE=podman) and nothing else.
#   CVESCAN_PYTHON_IMAGE   base image to build on, when Docker Hub is not reachable
#   CVESCAN_TEST_HOST      address of this machine as seen from a container
#                          (default: the bridge gateway; on Docker Desktop use host.docker.internal)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(dirname "$HERE")"
VERBOSE=0; [ "${1:-}" = "-v" ] && VERBOSE=1
ENGINE_NAME="${CVESCAN_ENGINE:-docker}"
REAL_ENGINE="$(command -v "$ENGINE_NAME")" || { echo "找不到 ${ENGINE_NAME}"; exit 2; }
"$REAL_ENGINE" info >/dev/null 2>&1 || { echo "${ENGINE_NAME} 沒有在執行"; exit 2; }
TEST_HOST="${CVESCAN_TEST_HOST:-$("$REAL_ENGINE" network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)}"
[ -n "$TEST_HOST" ] || { echo "無法判斷 container 連回本機的位址,請設定 CVESCAN_TEST_HOST"; exit 2; }
VERSION="$(head -n 1 "$ROOT/VERSION")"
IMAGE="cvescan:${VERSION}"

W="$(mktemp -d)"
PORT=$((20000 + RANDOM % 20000))
SERVER=""; TLS_SERVER=""
cleanup() {
  [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null
  [ -n "$TLS_SERVER" ] && kill "$TLS_SERVER" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

# A shim in front of the engine: records every call, one argument per line, then runs it for real.
mkdir -p "$W/shim" "$W/up" "$W/config" "$W/work" "$W/bin"
export ENGINE_LOG="$W/engine.log" REAL_ENGINE
cat > "$W/shim/$ENGINE_NAME" <<'SHIM'
#!/usr/bin/env bash
{ printf '%s\n' "$@"; printf '%s\n' "--END--"; } >> "$ENGINE_LOG"
exec "$REAL_ENGINE" "$@"
SHIM
chmod +x "$W/shim/$ENGINE_NAME"
export PATH="$W/shim:$PATH"

export CVESCAN_HOME="$W/reports" CVESCAN_STATE="$W/state" CVESCAN_CONFIG_DIR="$W/config" CVESCAN_BIN_DIR="$W/bin"
unset CVESCAN_IMAGE CVESCAN_SCANNER
[ "$ENGINE_NAME" = docker ] && unset CVESCAN_ENGINE
# The proxy of this shell is for this machine; the test upstream is reached directly.
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy SSL_CERT_FILE

cp -R "$HERE/fixtures/projects/shop-api" "$W/work/"
python3 "$HERE/fixtures/make_upstream.py" "$W/up" >/dev/null
write_config() {  # write_config <base url>
  cat > "$W/config/config.toml" <<EOF
[sources]
osv_base_url = "$1/osv"
kev_url = "$1/kev.json"
epss_url = "$1/epss.csv.gz"
eol_url_template = "$1/eol/{product}.json"
EOF
}
write_config "http://${TEST_HOST}:${PORT}"
(cd "$W/up" && exec python3 -m http.server "$PORT" --bind 0.0.0.0) >/dev/null 2>&1 &
SERVER=$!
sleep 1

PASS=0; FAIL=0; OUT=""; CODE=0
ok()   { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; [ "$VERBOSE" = 1 ] || printf '%s\n' "$OUT" | tail -n 15 | sed 's/^/        | /'; }
run()  { OUT="$("$@" 2>&1)"; CODE=$?; [ "$VERBOSE" = 1 ] && printf '%s\n' "----- $* (exit $CODE)" "$OUT"; return 0; }
code() { if [ "$CODE" = "$2" ]; then ok "$1"; else bad "$1 (exit $CODE, expected $2)"; fi; }
has()  { if printf '%s' "$OUT" | grep -qF -- "$2"; then ok "$1"; else bad "$1 (expected: $2)"; fi; }
q()    { python3 -c 'import json,sys; r=json.load(open(sys.argv[1], encoding="utf-8")); print(eval(sys.argv[2]))' "$1" "$2"; }
eq()   { local got; got="$(q "$2" "$3" 2>&1)"; if [ "$got" = "$4" ]; then ok "$1"; else OUT="$got"; bad "$1 (expected $4)"; fi; }

# probe <subcommand>: rerun that step's container with the flags the wrapper
# used, replacing only the program. Prints what it could reach, as JSON.
probe() {
  python3 - "$ENGINE_LOG" "$IMAGE" "$1" "$REAL_ENGINE" "$TEST_HOST" "$PORT" <<'PY'
import json, subprocess, sys
log, image, sub, engine, host, port = sys.argv[1:7]
calls, current = [], []
for line in open(log, encoding="utf-8").read().split("\n"):
    if line == "--END--":
        calls.append(current); current = []
    else:
        current.append(line)
matching = [c for c in calls if c[:1] == ["run"] and image in c and c[c.index(image) + 1:c.index(image) + 2] == [sub]]
if not matching:
    print(json.dumps({"error": "step was not run"})); sys.exit(0)
call = matching[-1]
flags = [a for a in call[:call.index(image)] if a != "-t"]
code = r'''
import json, os, socket, sys
def writable(path):
    if not os.path.isdir(path):
        return None
    try:
        probe = os.path.join(path, ".cvescan-probe")
        open(probe, "w").close(); os.remove(probe)
        return True
    except OSError:
        return False
result = {name: writable(name) for name in ("/src", "/db", "/out", "/state", "/config", "/", "/tmp", "/opt/cvescan")}
sock = socket.socket(); sock.settimeout(3)
try:
    sock.connect((sys.argv[1], int(sys.argv[2]))); result["net"] = True
except OSError:
    result["net"] = False
result["interfaces"] = sorted(os.listdir("/sys/class/net"))
result["uid"] = os.getuid()
status = dict(line.split(":\t", 1) for line in open("/proc/self/status").read().splitlines() if ":\t" in line)
result["cap_eff"] = status.get("CapEff"); result["no_new_privs"] = status.get("NoNewPrivs")
print(json.dumps(result, sort_keys=True))
'''
done = subprocess.run([engine] + flags + ["--entrypoint", "python3", image, "-c", code, host, port], capture_output=True, text=True)
print(done.stdout.strip() or json.dumps({"error": done.stderr[-400:]}))
PY
}
pq()   { printf '%s' "$PROBE" | python3 -c 'import json,sys; r=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1" 2>&1; }
peq()  { local got; got="$(pq "$2")"; if [ "$got" = "$3" ]; then ok "$1"; else OUT="$PROBE"; bad "$1 (got $got, expected $3)"; fi; }

echo "== install.sh: build the image, install the wrapper, download the database =="
run env CVESCAN_PREWARM="npm" "$ROOT/install.sh"
code "install.sh exits 0" 0
[ -x "$W/bin/cvescan" ] && ok "wrapper installed" || bad "wrapper not installed"
"$REAL_ENGINE" image inspect "$IMAGE" >/dev/null 2>&1 && ok "image ${IMAGE} exists" || bad "image missing"
[ -s "$W/state/db/osv/npm/all.zip" ] && ok "database downloaded during install" || bad "no database after install"
run "$REAL_ENGINE" run --rm --entrypoint python3 "$IMAGE" -c 'import sys; print([p for p in sys.modules if p.startswith("cvescan")], sys.version_info >= (3, 11))'
has  "image has Python 3.11 or newer" "True"
run "$REAL_ENGINE" run --rm --entrypoint python3 "$IMAGE" -c 'import os; print(sorted(os.listdir("/opt/cvescan/cvescan_core/data")))'
has  "image ships the agent instructions" "ANALYZE.md"

CV="$W/bin/cvescan"
SHOP="$W/work/shop-api"
R="$CVESCAN_HOME/shop-api/latest"
BEFORE="$(cd "$SHOP" && find . -type f -exec sha256sum {} + | sort | sha256sum)"

echo "== a scan in real containers =="
: > "$ENGINE_LOG"
run "$CV" "$SHOP"
code "scan exits 0" 0
has  "environment line" "環境   ${ENGINE_NAME} ✓"
has  "result line" "未解決 6"
eq   "quality complete" "$R/report.json" 'r["quality"]["status"]' complete
eq   "sample check passed inside the container" "$R/report.json" 'r["coverage"]["canary"]["npm"]' pass
eq   "scanner version recorded" "$R/report.json" 'r["tool"]["scanner"]' "osv-scanner 2.7.1"
eq   "dependency paths present" "$R/report.json" 'any(i["introduced_by"] for f in r["findings"] for i in f["instances"])' True
for f in report.json report.md sbom.cdx.json ANALYZE.md analysis.schema.json; do
  [ -s "$R/$f" ] && ok "wrote $f" || bad "missing $f"
done
[ "$(stat -c %u "$R/report.json" 2>/dev/null || stat -f %u "$R/report.json")" = "$(id -u)" ] && ok "report belongs to the caller" || bad "report owner is wrong"
AFTER="$(cd "$SHOP" && find . -type f -exec sha256sum {} + | sort | sha256sum)"
[ "$BEFORE" = "$AFTER" ] && ok "project folder untouched" || bad "project folder changed"

echo "== what each step can actually reach =="
PROBE="$(probe detect)"; [ "$VERBOSE" = 1 ] && echo "detect: $PROBE"
peq "detect: no network"                 'r["net"]' False
peq "detect: only a loopback interface"  'r["interfaces"]' "['lo']"
peq "detect: code is mounted read-only"  'r["/src"]' False
peq "detect: no database, reports or state" '(r["/db"], r["/out"], r["/state"])' "(None, None, None)"
PROBE="$(probe sync)"; [ "$VERBOSE" = 1 ] && echo "sync: $PROBE"
peq "sync: has the network"              'r["net"]' True
peq "sync: the code is not there at all" 'r["/src"]' None
peq "sync: no reports or state"          '(r["/out"], r["/state"])' "(None, None)"
peq "sync: can write the database"       'r["/db"]' True
PROBE="$(probe scan)"; [ "$VERBOSE" = 1 ] && echo "scan: $PROBE"
peq "scan: no network"                   'r["net"]' False
peq "scan: only a loopback interface"    'r["interfaces"]' "['lo']"
peq "scan: code is read-only"            'r["/src"]' False
peq "scan: database is read-only"        'r["/db"]' False
peq "scan: config is read-only"          'r["/config"]' False
peq "scan: can write reports and state"  '(r["/out"], r["/state"])' "(True, True)"
peq "scan: root filesystem is read-only" '(r["/"], r["/opt/cvescan"])' "(False, False)"
peq "scan: only /tmp is scratch space"   'r["/tmp"]' True
peq "scan: runs as the caller"           'r["uid"]' "$(id -u)"
peq "scan: no capabilities"              'int(r["cap_eff"], 16)' 0
peq "scan: no new privileges"            'r["no_new_privs"]' 1

echo "== verify and status in real containers =="
python3 "$HERE/fake_ai.py" "$R" good
: > "$ENGINE_LOG.keep"; cat "$ENGINE_LOG" >> "$ENGINE_LOG.keep"
run "$CV" verify shop-api
code "verify exits 0" 0
[ -s "$R/analysis.md" ] && ok "analysis.md rendered" || bad "analysis.md missing"
PROBE="$(probe verify)"; [ "$VERBOSE" = 1 ] && echo "verify: $PROBE"
peq "verify: no network"                  'r["net"]' False
peq "verify: the code is not there at all" 'r["/src"]' None
peq "verify: no database"                 'r["/db"]' None
python3 "$HERE/fake_ai.py" "$R" bad
run "$CV" verify shop-api
code "a bad analysis is rejected in the container too" 1
run "$CV" status shop-api
code "status exits 0" 0
has  "status shows the history" "shop-api|首次掃描"
PROBE="$(probe status)"; [ "$VERBOSE" = 1 ] && echo "status: $PROBE"
peq "status: no network"                  'r["net"]' False
peq "status: state is read-only"          'r["/state"]' False
peq "status: the code is not there at all" 'r["/src"]' None

echo "== a checkout made with a strict umask still gives a usable image =="
STRICT="$W/strict"
mkdir -p "$STRICT"
cp -R "$ROOT/Dockerfile" "$ROOT/.dockerignore" "$ROOT/core" "$STRICT/"
find "$STRICT" -name __pycache__ -prune -exec rm -rf {} +
chmod -R go-rwx "$STRICT"
STRICT_IMAGE="cvescan-test-strict:${VERSION}"
STRICT_ARGS=()
[ -n "${CVESCAN_PYTHON_IMAGE:-}" ] && STRICT_ARGS+=(--build-arg "PYTHON_IMAGE=${CVESCAN_PYTHON_IMAGE}")
run "$REAL_ENGINE" build -q ${STRICT_ARGS[@]+"${STRICT_ARGS[@]}"} -t "$STRICT_IMAGE" "$STRICT"
code "image builds from files only the owner can read" 0
run "$REAL_ENGINE" run --rm --read-only --cap-drop ALL --network none --user 54321:54321 "$STRICT_IMAGE" version
code "and another user can still run it" 0
has  "it reports its version" "$VERSION"
"$REAL_ENGINE" image rm "$STRICT_IMAGE" >/dev/null 2>&1

echo "== a private CA reaches the sync step and nothing else =="
if command -v openssl >/dev/null 2>&1; then
  TLS="$W/tls"; mkdir -p "$TLS"
  TLS_PORT=$((PORT + 1))
  case "$TEST_HOST" in
    *[!0-9.]*) SAN="DNS:${TEST_HOST}" ;;
    *) SAN="IP:${TEST_HOST}" ;;
  esac
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=cvescan test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout "$TLS/ca.key" -out "$TLS/ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj "/CN=cvescan test upstream" -keyout "$TLS/server.key" -out "$TLS/server.csr" >/dev/null 2>&1
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$SAN" > "$TLS/ext.cnf"
  openssl x509 -req -in "$TLS/server.csr" -CA "$TLS/ca.pem" -CAkey "$TLS/ca.key" -CAcreateserial -days 2 \
    -extfile "$TLS/ext.cnf" -out "$TLS/server.pem" >/dev/null 2>&1
  python3 - "$W/up" "$TLS_PORT" "$TLS/server.pem" "$TLS/server.key" >/dev/null 2>&1 <<'PY' &
import functools, http.server, ssl, sys
directory, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
server = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
  TLS_SERVER=$!
  sleep 1
  write_config "https://${TEST_HOST}:${TLS_PORT}"
  export CVESCAN_STATE="$W/state-tls" CVESCAN_HOME="$W/reports-tls"
  run "$CV" "$SHOP"
  code "an upstream signed by an unknown CA is not trusted: the scan is refused" 2
  has  "the refusal is about the database" "拒絕"
  : > "$ENGINE_LOG"
  run env SSL_CERT_FILE="$TLS/ca.pem" "$CV" "$SHOP"
  code "with the CA bundle of the calling shell the same scan works" 0
  eq   "and it is a complete scan" "$CVESCAN_HOME/shop-api/latest/report.json" 'r["quality"]["status"]' complete
  python3 - "$ENGINE_LOG" "$IMAGE" > "$W/ca-steps" <<'PY'
import sys
log, image = sys.argv[1:3]
calls, current = [], []
for line in open(log, encoding="utf-8").read().split("\n"):
    if line == "--END--":
        calls.append(current); current = []
    else:
        current.append(line)
steps = sorted({c[c.index(image) + 1] for c in calls if c[:1] == ["run"] and image in c and any("cvescan-ca.pem" in a for a in c)})
print(steps)
PY
  OUT="$(cat "$W/ca-steps")"
  [ "$OUT" = "['sync', 'update-check']" ] && ok "only the network steps were given the CA bundle" || bad "CA bundle given to: $OUT"
  export CVESCAN_STATE="$W/state-tls-install"
  run env CVESCAN_PREWARM="npm" SSL_CERT_FILE="$TLS/ca.pem" "$ROOT/install.sh"
  [ -s "$CVESCAN_STATE/db/osv/npm/all.zip" ] && ok "the download in install.sh uses the CA bundle too" || bad "install.sh did not download through the private CA"
else
  echo "  skip  openssl not found"
fi

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" = 0 ]
