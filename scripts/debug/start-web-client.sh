#!/bin/bash

# Script to run Chromium inside a dedicated network, mount, and PID namespace.
# This ensures true process isolation, preventing new instances from attaching
# to existing ones.
# Usage: ./start-web-client.sh [namespace]

set -e

# Get namespace from argument or default to appsns
APPS_NS="${1:-appsns}"

echo "Starting Chromium in ${APPS_NS} namespace..."

# Check if namespace exists
if ! sudo ip netns list | grep -q "^${APPS_NS}"; then
    echo "Error: ${APPS_NS} namespace does not exist"
    echo "Available namespaces:"
    sudo ip netns list
    echo ""
    echo "Usage: $0 [appsns|appsns2]"
    exit 1
fi

# Get the user who invoked sudo
APP_USER=${SUDO_USER:-$USER}
APP_UID=$(id -u "${APP_USER}")
APP_GID=$(id -g "${APP_USER}")

if [[ -z "${APP_UID}" ]]; then
  echo "[kidos] warning: unable to determine UID for ${APP_USER}; skipping chromium launch" >&2
  exit 1
fi

# Define paths on the HOST filesystem
USER_DATA_DIR="/tmp/chrom-${APPS_NS}"
CHROM_LOG="${USER_DATA_DIR}/chromium.log"

# Create user data directory on the host so we can bind-mount it
mkdir -p "${USER_DATA_DIR}"
touch "${CHROM_LOG}"
chown -R "${APP_USER}:${APP_USER}" "${USER_DATA_DIR}"

# Get namespace IP for window title
NS_IP=$(sudo ip netns exec "${APPS_NS}" ip -4 addr show veth-app | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "unknown")

echo "[kidos] Namespace: ${APPS_NS}"
echo "[kidos] IP: ${NS_IP}"
echo "[kidos] User: ${APP_USER} (UID: ${APP_UID})"
echo "[kidos] Profile/Log Path: ${USER_DATA_DIR}"
echo ""

# --- THE FIX IS HERE ---
# Use `ip netns exec` to handle the network namespace, and `unshare` for the rest.
# This is a more robust pattern than using `unshare --net=...`.
sudo ip netns exec "${APPS_NS}" unshare --mount --pid --fork --propagation=private bash <<EOF &
# --- This part of the script runs as root inside the new mount/pid namespaces ---
# --- AND the existing network namespace ---

# NOTE: At this point, /tmp still points to the host's /tmp

# 1. CRITICAL: Bind mount the host's profile directory BEFORE creating new /tmp
#    We bind it to a temporary location that won't be affected by the tmpfs mount
mkdir -p /run/kidos-profile-${APPS_NS}
mount --bind "${USER_DATA_DIR}" /run/kidos-profile-${APPS_NS}

# 2. Save reference to X11 sockets before replacing /tmp
mkdir -p /run/kidos-x11
mount --bind /tmp/.X11-unix /run/kidos-x11 2>/dev/null || true

# 3. Create a new, private /tmp (this hides the host's /tmp)
mount -t tmpfs tmpfs /tmp

# 4. Restore X11 sockets in the new /tmp
mkdir -p /tmp/.X11-unix
mount --bind /run/kidos-x11 /tmp/.X11-unix 2>/dev/null || true

# 5. Restore profile directory in the new /tmp at the correct path
mkdir -p "${USER_DATA_DIR}"
mount --bind /run/kidos-profile-${APPS_NS} "${USER_DATA_DIR}"
chown -R "${APP_UID}:${APP_GID}" "${USER_DATA_DIR}"

# 6. Create and mount a private runtime directory for the user
mkdir -p "/run/user/${APP_UID}"
mount -t tmpfs tmpfs "/run/user/${APP_UID}"
chown "${APP_UID}:${APP_GID}" "/run/user/${APP_UID}"

# 6b. Copy .Xauthority for X11 authentication
if [ -f "/home/${APP_USER}/.Xauthority" ]; then
  cp "/home/${APP_USER}/.Xauthority" "/run/user/${APP_UID}/.Xauthority"
  chown "${APP_UID}:${APP_GID}" "/run/user/${APP_UID}/.Xauthority"
fi

# 7. Drop privileges and launch Chromium as the original user.
#    The browser is launched in the background (&) within the namespace.
sudo -u "${APP_USER}" env DISPLAY="${DISPLAY:-:0}" \
                          XAUTHORITY="/run/user/${APP_UID}/.Xauthority" \
                          XDG_RUNTIME_DIR="/run/user/${APP_UID}" \
                          WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
  /usr/bin/chromium-browser \
    --user-data-dir="${USER_DATA_DIR}" \
    --no-sandbox \
    --disable-dev-shm-usage \
    --window-name="Browser (${APPS_NS} - ${NS_IP})" \
    >> "${CHROM_LOG}" 2>&1 &

# 8. Keep the namespace alive. If this script exits, the namespace is destroyed.
#    This is why 'sleep infinity' is used.
sleep infinity
EOF

# Give it a moment to start
sleep 2

echo "[kidos] Chromium launch command issued for ${APPS_NS} (${NS_IP})"
echo "[kidos] Check logs: tail -f ${CHROM_LOG}"
echo "[kidos] Check processes: ps aux | grep chrom-${APPS_NS}"
