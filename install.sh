#!/usr/bin/env bash
# Build the cvescan image, put the wrapper on PATH, and download the
# vulnerability databases once so the first scan is not slow.
#
#   ./install.sh
#   CVESCAN_PREWARM="npm,PyPI" ./install.sh     # which databases to download now
#   CVESCAN_PREWARM="" ./install.sh             # skip the download
#   CVESCAN_PYTHON_IMAGE=registry.internal/python:3.13-slim ./install.sh
#                                               # base image from another registry (Python 3.11 or newer)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ENGINE="${CVESCAN_ENGINE:-docker}"
VERSION="$(head -n 1 "$HERE/VERSION")"
IMAGE="cvescan:${VERSION}"
BIN_DIR="${CVESCAN_BIN_DIR:-$HOME/.local/bin}"
STATE_ROOT="${CVESCAN_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/cvescan}"
CONFIG_DIR="${CVESCAN_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/cvescan}"
PREWARM="${CVESCAN_PREWARM-npm,PyPI,Packagist}"
REPORTS_ROOT="${CVESCAN_HOME:-$HOME/cvescan}"

# Reports go to ~/cvescan by default, which is also where a clone of this
# repository lands when it is cloned from the home folder. Stop before the
# first scan writes reports into the source tree.
REPORTS_REAL="$REPORTS_ROOT"
if [ -d "$REPORTS_ROOT" ]; then REPORTS_REAL="$(cd "$REPORTS_ROOT" && pwd -P)"; fi
case "$HERE/" in
  "$REPORTS_REAL"/*)
    echo "原始碼在 ${HERE},而 ${REPORTS_ROOT} 是 cvescan 放報表的資料夾。" >&2
    echo "請把原始碼移到別處(例如 ~/src/cvescan)再安裝,或用 CVESCAN_HOME 指定另一個報表資料夾。" >&2
    exit 2 ;;
esac
case "$REPORTS_REAL/" in
  "$HERE"/*)
    echo "報表資料夾 ${REPORTS_ROOT} 在原始碼資料夾 ${HERE} 裡面。" >&2
    echo "請用 CVESCAN_HOME 指定原始碼之外的報表資料夾。" >&2
    exit 2 ;;
esac

command -v "$ENGINE" >/dev/null 2>&1 || { echo "找不到 ${ENGINE}。請先安裝 Docker:https://docs.docker.com/get-docker/" >&2; exit 2; }
"$ENGINE" info >/dev/null 2>&1 || { echo "${ENGINE} 沒有在執行。" >&2; exit 2; }

echo "建置映像 ${IMAGE} …"
BUILD_ARGS=()
if [ -n "${CVESCAN_PYTHON_IMAGE:-}" ]; then
  BUILD_ARGS+=(--build-arg "PYTHON_IMAGE=${CVESCAN_PYTHON_IMAGE}")
fi
"$ENGINE" build ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} -t "$IMAGE" "$HERE"

mkdir -p "$BIN_DIR" "$STATE_ROOT/db" "$STATE_ROOT/projects" "$CONFIG_DIR"
install -m 0755 "$HERE/cvescan" "$BIN_DIR/cvescan"
rm -f "$STATE_ROOT/image"   # a fresh install uses the image that was just built
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  install -m 0644 "$HERE/config.example.toml" "$CONFIG_DIR/config.toml"
fi

if [ -n "$PREWARM" ]; then
  echo "下載漏洞資料庫(${PREWARM})…第一次會比較久"
  # Same access as the wrapper's sync step: network, the database folder, no code.
  # The proxy and CA bundle of this shell apply, as they do in the wrapper.
  NET_ARGS=()
  for var in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy; do
    value="${!var:-}"
    [ -n "$value" ] || continue
    case "$var:$value" in
      [Nn][Oo]_*) ;;
      *://localhost[:/]*|*://localhost|*://127.*|*://\[::1\]*|*:localhost:*|*:127.*) continue ;;
    esac
    NET_ARGS+=(-e "$var")
  done
  if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "$SSL_CERT_FILE" ]; then
    CA="$(cd "$(dirname "$SSL_CERT_FILE")" && pwd -P)/$(basename "$SSL_CERT_FILE")"   # a mount source must be absolute
    case "$CA" in
      *,*|*\"*) ;;
      *) NET_ARGS+=(--mount "type=bind,source=${CA},target=/etc/cvescan-ca.pem,readonly" -e "SSL_CERT_FILE=/etc/cvescan-ca.pem") ;;
    esac
  fi
  "$ENGINE" run --rm --read-only --tmpfs /tmp:rw,nosuid,size=1g --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 512 --user "$(id -u):$(id -g)" -e HOME=/tmp \
    ${NET_ARGS[@]+"${NET_ARGS[@]}"} \
    --mount "type=bind,source=${STATE_ROOT}/db,target=/db" \
    --mount "type=bind,source=${CONFIG_DIR},target=/config,readonly" \
    "$IMAGE" sync --ecosystems "$PREWARM" || echo "資料庫下載沒有完成;第一次掃描時會再試一次。"
fi

echo
echo "安裝完成:${BIN_DIR}/cvescan"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "請把 ${BIN_DIR} 加進 PATH。" ;;
esac
echo "開始使用:cvescan <專案路徑>"
