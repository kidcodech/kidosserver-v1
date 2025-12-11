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

# Attempt to find the user's Xauthority file
REAL_XAUTH=""

# 1. Check if XAUTHORITY env var is set and valid
if [ -n "$XAUTHORITY" ] && [ -f "$XAUTHORITY" ]; then
    REAL_XAUTH="$XAUTHORITY"
fi

# 2. Check standard locations if not found
if [ -z "$REAL_XAUTH" ]; then
    CANDIDATES=(
        "/run/user/${APP_UID}/gdm/Xauthority"
        "/run/user/${APP_UID}/.mutter-Xwaylandauth"
        "/home/${APP_USER}/.Xauthority"
    )
    for cand in "${CANDIDATES[@]}"; do
        if [ -f "$cand" ]; then
            REAL_XAUTH="$cand"
            break
        fi
    done
fi

if [ -z "$REAL_XAUTH" ]; then
    echo "[kidos] Warning: Could not find Xauthority file. GUI might fail."
else
    echo "[kidos] Using Xauthority: ${REAL_XAUTH}"
fi

# --- THE FIX IS HERE ---
# Use `ip netns exec` to handle the network namespace, and `unshare` for the rest.
# This is a more robust pattern than using `unshare --net=...`.
# Redirect output to a debug log in /var/tmp to capture startup errors
DEBUG_LOG="/var/tmp/kidos-startup-${APPS_NS}.log"
echo "Debug log: ${DEBUG_LOG}"

# Define XAUTH_BACKUP in outer shell so it expands correctly in heredoc
XAUTH_BACKUP="/tmp/.Xauthority.backup"

sudo ip netns exec "${APPS_NS}" unshare --mount --pid --fork --propagation=private bash <<EOF > "${DEBUG_LOG}" 2>&1 &
# --- This part of the script runs as root inside the new mount/pid namespaces ---
# --- AND the existing network namespace ---

set -x # Enable debug tracing

# NOTE: At this point, /tmp still points to the host's /tmp

# 1. CRITICAL: Bind mount the host's profile directory BEFORE creating new /tmp
#    We bind it to a temporary location that won't be affected by the tmpfs mount
mkdir -p /run/kidos-profile-${APPS_NS}
if ! mount --bind "${USER_DATA_DIR}" /run/kidos-profile-${APPS_NS}; then
    echo "Failed to bind mount profile dir"
    exit 1
fi

# 2. Save reference to X11 sockets before replacing /tmp
mkdir -p /run/kidos-x11
if ! mount --bind /tmp/.X11-unix /run/kidos-x11 2>/dev/null; then
    echo "Warning: Failed to bind mount X11 socket (might not exist)"
fi

# 3. Create a new, private /tmp (this hides the host's /tmp)
if ! mount -t tmpfs tmpfs /tmp; then
    echo "Failed to mount tmpfs over /tmp"
    exit 1
fi

# 4. Restore X11 sockets in the new /tmp
mkdir -p /tmp/.X11-unix
if ! mount --bind /run/kidos-x11 /tmp/.X11-unix 2>/dev/null; then
    echo "Warning: Failed to restore X11 socket"
fi

# 5. Restore profile directory in the new /tmp at the correct path
mkdir -p "${USER_DATA_DIR}"
if ! mount --bind /run/kidos-profile-${APPS_NS} "${USER_DATA_DIR}"; then
    echo "Failed to restore profile dir"
    exit 1
fi
chown -R "${APP_UID}:${APP_GID}" "${USER_DATA_DIR}"

# 5b. Pre-stage Xauthority BEFORE we mount over /run/user/${APP_UID}
#     If the Xauthority file is in /run/user/${APP_UID} (which is common),
#     it will be hidden by the next step. We copy it to our new /tmp first.
if [ -n "${REAL_XAUTH}" ] && [ -f "${REAL_XAUTH}" ]; then
    echo "Backing up Xauthority from ${REAL_XAUTH} to ${XAUTH_BACKUP}"
    cp "${REAL_XAUTH}" "${XAUTH_BACKUP}"
    # Make sure root can read it to copy it back later
    chmod 600 "${XAUTH_BACKUP}"
else
    echo "Warning: Xauthority file ${REAL_XAUTH} not found or empty before backup"
fi

# 6. Create and mount a private runtime directory for the user
mkdir -p "/run/user/${APP_UID}"
mount -t tmpfs tmpfs "/run/user/${APP_UID}"
chown "${APP_UID}:${APP_GID}" "/run/user/${APP_UID}"

# 6b. Copy .Xauthority for X11 authentication
if [ -f "${XAUTH_BACKUP}" ]; then
  echo "Restoring Xauthority from backup..."
  cp "${XAUTH_BACKUP}" "/run/user/${APP_UID}/.Xauthority"
  chown "${APP_UID}:${APP_GID}" "/run/user/${APP_UID}/.Xauthority"
  chmod 600 "/run/user/${APP_UID}/.Xauthority"
elif [ -n "${REAL_XAUTH}" ] && [ -f "${REAL_XAUTH}" ]; then
  # Fallback: if it wasn't in /run/user/UID (e.g. it was in /home), we can still see it
  echo "Copying Xauthority directly from ${REAL_XAUTH}..."
  cp "${REAL_XAUTH}" "/run/user/${APP_UID}/.Xauthority"
  chown "${APP_UID}:${APP_GID}" "/run/user/${APP_UID}/.Xauthority"
  chmod 600 "/run/user/${APP_UID}/.Xauthority"
else
  echo "Warning: No Xauthority file available to setup"
fi

# 7. Drop privileges and launch Chromium as the original user.
#    The browser is launched in the background (&) within the namespace.
echo "Launching Chromium..."
sudo -u "${APP_USER}" env DISPLAY="${DISPLAY:-:0}" \
                          XAUTHORITY="/run/user/${APP_UID}/.Xauthority" \
                          XDG_RUNTIME_DIR="/run/user/${APP_UID}" \
                          WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
  /usr/bin/chromium-browser \
    --user-data-dir="${USER_DATA_DIR}" \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-features=DnsOverHttps \
    --disable-quic \
    --window-name="Browser (${APPS_NS} - ${NS_IP})" \
    >> "${CHROM_LOG}" 2>&1 &

CHROM_PID=\$!
echo "Chromium launched with PID \$CHROM_PID"

# 8. Keep the namespace alive. If this script exits, the namespace is destroyed.
#    This is why 'sleep infinity' is used.
wait \$CHROM_PID
EOF

# Give it a moment to start
sleep 2

echo "[kidos] Chromium launch command issued for ${APPS_NS} (${NS_IP})"
echo "[kidos] Check logs: tail -f ${CHROM_LOG}"
echo "[kidos] Check debug logs: tail -f ${DEBUG_LOG}"
echo "[kidos] Check processes: ps aux | grep chrom-${APPS_NS}"
