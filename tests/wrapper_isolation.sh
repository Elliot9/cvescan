#!/usr/bin/env bash
# Checks what the wrapper asks the container engine for at each step:
# which steps get the network, which get the code, and what is read-only.
# Uses a fake `docker` that records its arguments (tests/stubs/docker).
#
#   CVESCAN_SCANNER=/path/to/osv-scanner tests/wrapper_isolation.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(dirname "$HERE")"
: "${CVESCAN_SCANNER:?set CVESCAN_SCANNER to an osv-scanner binary}"

W="$(mktemp -d)"
PORT=$((20000 + RANDOM % 20000))
SERVER=""
cleanup() { [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

export PATH="$HERE/stubs:$PATH" PYTHONPATH="$ROOT/core" CVESCAN_SCANNER
export DOCKER_STUB_LOG="$W/docker.log"
export CVESCAN_HOME="$W/reports" CVESCAN_STATE="$W/state" CVESCAN_CONFIG_DIR="$W/config"
unset CVESCAN_ENGINE CVESCAN_IMAGE
chmod +x "$HERE/stubs/docker"
mkdir -p "$W/up" "$W/config" "$W/work"
cp -R "$HERE/fixtures/projects/shop-api" "$W/work/"
python3 "$HERE/fixtures/make_upstream.py" "$W/up"
HEX="$(printf 'b%.0s' $(seq 1 64))"
printf '{"version":"0.2.0","released_at":"2026-01-01T00:00:00Z","image":"registry.example/cvescan@sha256:%s","min_supported":"0.1.0"}' "$HEX" > "$W/up/update.json"
cat > "$W/config/config.toml" <<CFG
[update]
manifest_url = "http://127.0.0.1:${PORT}/update.json"
[sources]
osv_base_url = "http://127.0.0.1:${PORT}/osv"
kev_url = "http://127.0.0.1:${PORT}/kev.json"
epss_url = "http://127.0.0.1:${PORT}/epss.csv.gz"
eol_url_template = "http://127.0.0.1:${PORT}/eol/{product}.json"
CFG
(cd "$W/up" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) >/dev/null 2>&1 &
SERVER=$!
sleep 1

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  ok    $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }
line() { grep -E -- " cvescan[^ ]* $1( |\$)| registry.example/[^ ]* $1( |\$)" "$DOCKER_STUB_LOG" | tail -n 1; }
want() { if printf '%s' "$2" | grep -qF -- "$3"; then ok "$1"; else bad "$1 (missing: $3)"; fi; }
deny() { if printf '%s' "$2" | grep -qF -- "$3"; then bad "$1 (present: $3)"; else ok "$1"; fi; }

# A corporate setup: a proxy that is not on this machine, and a private CA bundle.
printf 'not a real certificate\n' > "$W/corp-ca.pem"
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy SSL_CERT_FILE
# The CA bundle is given as a relative path on purpose: a mount source has to be absolute.
REAL_W="$(cd "$W" && pwd -P)"
OUT="$(cd "$W" && https_proxy="http://proxy.corp.example:3128" NO_PROXY="localhost,127.0.0.1" SSL_CERT_FILE="corp-ca.pem" "$ROOT/cvescan" "$W/work/shop-api" 2>&1)"; CODE=$?
[ "$CODE" = 0 ] && ok "scan through the container path exits 0" || { bad "scan exit $CODE"; printf '%s\n' "$OUT"; }
want "environment line names the engine" "$OUT" "環境   docker ✓"
want "unattended run took the cooled-down update" "$OUT" "已更新到 0.2.0"
grep -q "^pull registry.example/cvescan@sha256:$HEX" "$DOCKER_STUB_LOG" && ok "image pulled by digest" || bad "no pull by digest"
[ "$(cat "$CVESCAN_STATE/image" 2>/dev/null)" = "registry.example/cvescan@sha256:$HEX" ] && ok "new image reference remembered" || bad "image reference not stored"

DETECT="$(line detect)"; SYNC="$(line sync)"; SCAN="$(line scan)"
want "detect: no network"            "$DETECT" "--network none"
want "detect: code is read-only"     "$DETECT" "target=/src,readonly"
deny "detect: no database mount"     "$DETECT" "target=/db"
deny "detect: no report mount"       "$DETECT" "target=/out"
deny "sync: network allowed"         "$SYNC"   "--network none"
deny "sync: never sees the code"     "$SYNC"   "target=/src"
deny "sync: never sees the reports"  "$SYNC"   "target=/out"
want "sync: writes the database"     "$SYNC"   "target=/db "
want "scan: no network"              "$SCAN"   "--network none"
want "scan: code is read-only"       "$SCAN"   "target=/src,readonly"
want "scan: database is read-only"   "$SCAN"   "target=/db,readonly"
want "scan: config is read-only"     "$SCAN"   "target=/config,readonly"
want "scan: uses the updated image"  "$SCAN"   "registry.example/cvescan@sha256:$HEX scan"
want "sync: gets the caller's proxy"          "$SYNC" "-e https_proxy"
want "sync: gets the caller's NO_PROXY"       "$SYNC" "-e NO_PROXY"
want "sync: gets the caller's CA bundle"      "$SYNC" "source=$REAL_W/corp-ca.pem,target=/etc/cvescan-ca.pem,readonly -e SSL_CERT_FILE=/etc/cvescan-ca.pem"
for step in "$DETECT" "$SCAN"; do
  deny "no proxy settings on a step that sees code" "$step" "proxy"
  deny "no CA bundle on a step that sees code"      "$step" "cvescan-ca.pem"
done
for step in "$DETECT" "$SYNC" "$SCAN"; do
  want "hardening: read-only root"   "$step" "--read-only"
  want "hardening: no capabilities"  "$step" "--cap-drop ALL"
  want "hardening: no new privileges" "$step" "no-new-privileges"
  want "hardening: runs as the caller" "$step" "--user $(id -u):$(id -g)"
done

python3 "$HERE/fake_ai.py" "$CVESCAN_HOME/shop-api/latest" good
OUT="$("$ROOT/cvescan" verify shop-api 2>&1)"; CODE=$?
[ "$CODE" = 0 ] && ok "verify through the container path exits 0" || { bad "verify exit $CODE"; printf '%s\n' "$OUT"; }
VERIFY="$(line verify)"
want "verify: no network"            "$VERIFY" "--network none"
deny "verify: never sees the code"   "$VERIFY" "target=/src"
deny "verify: no database mount"     "$VERIFY" "target=/db"
OUT="$("$ROOT/cvescan" status 2>&1)"
STATUS="$(line status)"
want "status: no network"            "$STATUS" "--network none"
want "status: state is read-only"    "$STATUS" "target=/state,readonly"
deny "status: never sees the code"   "$STATUS" "target=/src"
want "status prints the project"     "$OUT" "shop-api"

# A proxy on this machine cannot be reached from inside a container: it is not passed on.
: > "$DOCKER_STUB_LOG"
OUT="$(HTTPS_PROXY="http://127.0.0.1:3128" http_proxy="localhost:3128" "$ROOT/cvescan" "$W/work/shop-api" 2>&1)"
SYNC="$(line sync)"
[ -n "$SYNC" ] && ok "second scan ran" || bad "second scan did not reach sync"
deny "sync: a localhost proxy is not passed on" "$SYNC" "PROXY"
deny "sync: a schemeless localhost proxy is not passed on" "$SYNC" "http_proxy"

# --mount is a comma-separated list: a path that would break out of it is refused, not mangled.
mkdir -p "$W/work/odd,readonly=false"
cp "$HERE/fixtures/projects/shop-api/package-lock.json" "$W/work/odd,readonly=false/"
: > "$DOCKER_STUB_LOG"
OUT="$("$ROOT/cvescan" "$W/work/odd,readonly=false" 2>&1)"; CODE=$?
[ "$CODE" = 2 ] && ok "a project path with a comma is refused" || bad "comma path: exit $CODE"
want "the refusal says why" "$OUT" "逗號"
grep -q " detect" "$DOCKER_STUB_LOG" && bad "a container was started for the comma path" || ok "no container is started for it"

# The repository and the default reports folder share a name. A clone must never become the reports folder.
CLONE="$W/home/cvescan"
mkdir -p "$CLONE/core/cvescan_core"
cp "$ROOT/install.sh" "$ROOT/VERSION" "$CLONE/"
: > "$DOCKER_STUB_LOG"
OUT="$(CVESCAN_HOME="$CLONE" "$ROOT/cvescan" "$W/work/shop-api" 2>&1)"; CODE=$?
[ "$CODE" = 2 ] && ok "a source checkout is refused as the reports folder" || bad "source checkout as reports folder: exit $CODE"
want "the refusal says why" "$OUT" "原始碼資料夾"
grep -q "^run " "$DOCKER_STUB_LOG" && bad "a container was started anyway" || ok "no container is started for it"
[ -z "$(find "$CLONE" -name latest)" ] && ok "nothing was written into the checkout" || bad "reports were written into the checkout"
: > "$DOCKER_STUB_LOG"
OUT="$(unset CVESCAN_HOME; HOME="$W/home" CVESCAN_PREWARM="" "$CLONE/install.sh" 2>&1)"; CODE=$?
[ "$CODE" = 2 ] && ok "install.sh stops when the source sits in the default reports folder" || bad "install from ~/cvescan: exit $CODE"
want "it says where to move the source" "$OUT" "移到別處"
grep -q "^build " "$DOCKER_STUB_LOG" && bad "the image was built anyway" || ok "nothing is built in that case"
OUT="$(HOME="$W/home" CVESCAN_HOME="$W/home/cvescan/reports" CVESCAN_PREWARM="" "$CLONE/install.sh" 2>&1)"; CODE=$?
[ "$CODE" = 2 ] && ok "a reports folder inside the source is refused too" || bad "reports inside source: exit $CODE"
want "it says to pick a folder outside the source" "$OUT" "原始碼之外"

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" = 0 ]
