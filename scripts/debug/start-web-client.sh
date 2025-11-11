#!/bin/bash

# Script to run Chromium inside appsns namespace for debugging
# This allows testing the monitoring system from within the isolated network namespace

set -e

echo "Starting Chromium in appsns namespace..."

# Check if appsns exists
if ! sudo ip netns list | grep -q "appsns"; then
    echo "Error: appsns namespace does not exist"
    echo "Please run scripts/ns-init.sh first"
    exit 1
fi

# Run Chromium in appsns
CHROMIUM="/usr/bin/chromium-browser"
APPS_NS="appsns"
APP_USER=${SUDO_USER:-$USER}

if [[ -x "${CHROMIUM}" ]]; then
  APP_UID=$(id -u "${APP_USER}" 2>/dev/null || true)
  if [[ -z "${APP_UID}" ]]; then
    echo "[kidos] warning: unable to determine UID for ${APP_USER}; skipping chromium launch" >&2
    exit 1
  else
    CHROM_LOG="/tmp/chrom-${APPS_NS}.log"
    touch "${CHROM_LOG}"
    chown "${APP_USER}:${APP_USER}" "${CHROM_LOG}"
    ip netns exec "${APPS_NS}" sudo -u "${APP_USER}" bash -c \
      "nohup env DISPLAY='${DISPLAY:-}' XDG_RUNTIME_DIR='/run/user/${APP_UID}' WAYLAND_DISPLAY='${WAYLAND_DISPLAY:-}' '${CHROMIUM}' --user-data-dir=/tmp/chrom-${APPS_NS} --no-sandbox --disable-dev-shm-usage >'${CHROM_LOG}' 2>&1 & disown"
    echo "[kidos] chromium launched in ${APPS_NS}; logs at ${CHROM_LOG}" >&2
  fi
else
  echo "[kidos] warning: chromium-browser not found; skipping launch" >&2
  exit 1
fi
