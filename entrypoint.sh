#!/usr/bin/env bash
# Container entrypoint: runs PrufGate as the owner of the mounted /workspace, so
# reports are not left root-owned on the host.
set -e

export HOME="/home/prufgate"
AS_USER=()

if [ "$(id -u)" -eq 0 ]; then
  WORKSPACE_UID=$(stat -c '%u' /workspace 2>/dev/null || echo 1000)
  WORKSPACE_GID=$(stat -c '%g' /workspace 2>/dev/null || echo 1000)
  if [ "${WORKSPACE_UID}" -eq 0 ]; then
    WORKSPACE_UID=1000
    WORKSPACE_GID=1000
  fi
  PRUFGATE_UID="${PRUFGATE_UID:-$WORKSPACE_UID}"
  PRUFGATE_GID="${PRUFGATE_GID:-$WORKSPACE_GID}"
  getent group "${PRUFGATE_GID}" >/dev/null 2>&1 || groupmod -g "${PRUFGATE_GID}" prufgategroup 2>/dev/null || groupadd -g "${PRUFGATE_GID}" prufgategroup 2>/dev/null || true
  getent passwd "${PRUFGATE_UID}" >/dev/null 2>&1 || usermod -u "${PRUFGATE_UID}" -g "${PRUFGATE_GID}" prufgateuser 2>/dev/null || useradd -u "${PRUFGATE_UID}" -g "${PRUFGATE_GID}" -d /home/prufgate -s /bin/bash prufgateuser 2>/dev/null || true
  chown -R "${PRUFGATE_UID}:${PRUFGATE_GID}" /home/prufgate 2>/dev/null || true
  mkdir -p /workspace/reports
  chown -R "${PRUFGATE_UID}:${PRUFGATE_GID}" /workspace/reports 2>/dev/null || true
  AS_USER=(gosu "${PRUFGATE_UID}:${PRUFGATE_GID}")
fi

mkdir -p /workspace/reports 2>/dev/null || true

case "${1:-fast}" in
  fast|check|review|full|all|bola|test-audit|test|init|mcp|api|--self-check|--version)
    exec "${AS_USER[@]}" /tools/prufgate/prufgate.sh "${@:-fast}" ;;
  --help|-h|help)
    exec "${AS_USER[@]}" python3 -I /tools/prufgate/prufgate/cli.py --help ;;
  *)
    exec "${AS_USER[@]}" "$@" ;;
esac
