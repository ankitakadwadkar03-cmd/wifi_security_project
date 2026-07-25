#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_USER="${SUDO_USER:-$USER}"

SCANNER_INSTALL_ROOT="/opt/netshield-scanner"
SCANNER_APP_DIR="${SCANNER_INSTALL_ROOT}/app"
SCANNER_VENV_DIR="${SCANNER_INSTALL_ROOT}/venv"

SERVICE_NAME="netshield-scanner.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
SUDOERS_PATH="/etc/sudoers.d/netshield-scanner"

OUTPUT_DIRECTORY="${PROJECT_ROOT}/scan_results"
OUTPUT_FILE="${OUTPUT_DIRECTORY}/wifi_scan_results.csv"

required_files=(
  "${PROJECT_ROOT}/scanner/wifi_scanner.py"
  "${PROJECT_ROOT}/scanner/csv_logger.py"
  "${PROJECT_ROOT}/scanner/network_parser.py"
)

for required_file in "${required_files[@]}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "Required scanner file not found: ${required_file}" >&2
    exit 1
  fi
done

echo "Installing protected NetShield scanner files..."

sudo install -d -m 0755 "${SCANNER_APP_DIR}"

sudo install -m 0644 \
  "${PROJECT_ROOT}/scanner/wifi_scanner.py" \
  "${PROJECT_ROOT}/scanner/csv_logger.py" \
  "${PROJECT_ROOT}/scanner/network_parser.py" \
  "${SCANNER_APP_DIR}/"

echo "Creating dedicated Python environment..."

if [[ ! -x "${SCANNER_VENV_DIR}/bin/python" ]]; then
  sudo python3 -m venv "${SCANNER_VENV_DIR}"
fi

sudo "${SCANNER_VENV_DIR}/bin/python" \
  -m pip install "scapy>=2.5.0"

mkdir -p "${OUTPUT_DIRECTORY}"

cat <<SERVICE_EOF | sudo tee "${SERVICE_PATH}" > /dev/null
[Unit]
Description=NetShield WiFi Security Scanner
After=network.target
ConditionPathExists=${SCANNER_APP_DIR}/wifi_scanner.py

[Service]
Type=simple
WorkingDirectory=${SCANNER_APP_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart=${SCANNER_VENV_DIR}/bin/python ${SCANNER_APP_DIR}/wifi_scanner.py --interface wlan0 --output ${OUTPUT_FILE}
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
echo "NetShield scanner service installed successfully."
echo "Service: ${SERVICE_NAME}"
echo "Project: ${PROJECT_ROOT}"
echo "User: ${CURRENT_USER}"
echo
echo "The service is intentionally not enabled at boot."
