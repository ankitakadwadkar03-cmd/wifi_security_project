#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_USER="${SUDO_USER:-$USER}"

CAPTURE_INSTALL_ROOT="/opt/netshield-capture"
CAPTURE_APP_DIR="${CAPTURE_INSTALL_ROOT}/app"
CAPTURE_VENV_DIR="${CAPTURE_INSTALL_ROOT}/venv"

SERVICE_NAME="netshield-capture.service"
SCANNER_SERVICE_NAME="netshield-scanner.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
SUDOERS_PATH="/etc/sudoers.d/netshield-capture"

OUTPUT_DIRECTORY="${PROJECT_ROOT}/packet_logs"
OUTPUT_FILE="${OUTPUT_DIRECTORY}/wifi_packets.csv"

required_files=(
  "${PROJECT_ROOT}/packet_capture/packet_sniffer.py"
  "${PROJECT_ROOT}/packet_capture/packet_analyzer.py"
  "${PROJECT_ROOT}/packet_capture/packet_logger.py"
)

for required_file in "${required_files[@]}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "Required packet-capture file not found: ${required_file}" >&2
    exit 1
  fi
done

echo "Installing protected NetShield packet-capture files..."

sudo install -d -m 0755 "${CAPTURE_APP_DIR}"

sudo install -m 0644 \
  "${PROJECT_ROOT}/packet_capture/packet_sniffer.py" \
  "${PROJECT_ROOT}/packet_capture/packet_analyzer.py" \
  "${PROJECT_ROOT}/packet_capture/packet_logger.py" \
  "${CAPTURE_APP_DIR}/"

echo "Creating dedicated Python environment..."

if [[ ! -x "${CAPTURE_VENV_DIR}/bin/python" ]]; then
  sudo python3 -m venv "${CAPTURE_VENV_DIR}"
fi

sudo "${CAPTURE_VENV_DIR}/bin/python" \
  -m pip install "scapy>=2.5.0"

mkdir -p "${OUTPUT_DIRECTORY}"

cat <<SERVICE_EOF | sudo tee "${SERVICE_PATH}" > /dev/null
[Unit]
Description=NetShield Live WiFi Packet Capture
After=network.target
ConditionPathExists=${CAPTURE_APP_DIR}/packet_sniffer.py

[Service]
Type=simple
WorkingDirectory=${CAPTURE_APP_DIR}
Environment=PYTHONUNBUFFERED=1

# Prevent capture from starting while scanning is active.
ExecStartPre=/bin/sh -c '! /usr/bin/systemctl is-active --quiet ${SCANNER_SERVICE_NAME}'

ExecStart=${CAPTURE_VENV_DIR}/bin/python ${CAPTURE_APP_DIR}/packet_sniffer.py --interface wlan0 --output ${OUTPUT_FILE}

KillSignal=SIGTERM
TimeoutStopSec=40
Restart=no
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

cat <<SUDOERS_EOF | sudo tee "${SUDOERS_PATH}" > /dev/null
${CURRENT_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start ${SERVICE_NAME}
${CURRENT_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl stop ${SERVICE_NAME}
${CURRENT_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl is-active ${SERVICE_NAME}
${CURRENT_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl show ${SERVICE_NAME} --property=MainPID --value
SUDOERS_EOF

sudo chmod 0440 "${SUDOERS_PATH}"
sudo visudo -cf "${SUDOERS_PATH}"
sudo systemctl daemon-reload

echo
echo "NetShield packet-capture service installed successfully."
echo "Service: ${SERVICE_NAME}"
echo "Project: ${PROJECT_ROOT}"
echo "User: ${CURRENT_USER}"
echo
echo "The service is intentionally not enabled at boot."
