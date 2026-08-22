#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run this installer as root (for example, sudo bash)." >&2
  exit 1
fi
: "${SERVER_URL:?ERROR: SERVER_URL is required}"
: "${ENROLLMENT_TOKEN:?ERROR: ENROLLMENT_TOKEN is required}"
SERVER_URL="${SERVER_URL%/}"
AGENT_VERSION="1.0.0"
INSTALL_DIR="/opt/ats-sensor"
CONFIG_FILE="$INSTALL_DIR/config.env"
AGENT_SCRIPT="$INSTALL_DIR/ats-agent.sh"
LOG_DIR="/var/log/ats-sensor"
case "$(uname -s)" in Linux) PLATFORM="linux" ;; Darwin) PLATFORM="macos" ;; *) echo "ERROR: unsupported OS" >&2; exit 1 ;; esac
for command_name in curl jq; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "ERROR: $command_name is required; install it and rerun." >&2
    exit 1
  }
done
HOSTNAME_VALUE="$(hostname)"
PAYLOAD="$(jq -n --arg token "$ENROLLMENT_TOKEN" --arg hostname "$HOSTNAME_VALUE" --arg platform "$PLATFORM" --arg os "$(uname -sr)" --arg version "$AGENT_VERSION" \
  '{enrollmentToken:$token,hostname:$hostname,platform:$platform,osVersion:$os,agentVersion:$version}')"
RESPONSE="$(curl --fail-with-body --silent --show-error --max-time 30 -X POST "$SERVER_URL/api/agent/v1/enroll" -H "Content-Type: application/json" --data "$PAYLOAD")"
SENSOR_ID="$(jq -er '.data.sensorId' <<<"$RESPONSE")"
API_KEY="$(jq -er '.data.apiKey' <<<"$RESPONSE")"
[[ "$API_KEY" == snx_agent_* ]] || { echo "ERROR: enrollment returned no sensor credential." >&2; exit 1; }
mkdir -p "$INSTALL_DIR" "$LOG_DIR"
umask 077
cat >"$CONFIG_FILE" <<EOF
SENSOR_ID=$(printf '%q' "$SENSOR_ID")
API_KEY=$(printf '%q' "$API_KEY")
SERVER_URL=$(printf '%q' "$SERVER_URL")
AGENT_VERSION=$(printf '%q' "$AGENT_VERSION")
PLATFORM=$(printf '%q' "$PLATFORM")
LOG_FILE=$(printf '%q' "$LOG_DIR/agent.log")
EOF
chmod 600 "$CONFIG_FILE"
cat >"$AGENT_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ats-sensor/config.env
api_post() {
  local path="$1" body="$2"
  curl --fail-with-body --silent --show-error --max-time 30 -X POST "$SERVER_URL$path" \
    -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" --data "$body"
}
heartbeat() {
  api_post "/api/agent/v1/sensors/$SENSOR_ID/heartbeat" \
    "$(jq -n --arg version "$AGENT_VERSION" '{cpuUsage:0,memoryUsage:0,diskUsage:0,agentVersion:$version,ipAddress:"127.0.0.1"}')" >/dev/null
}
send_events() {
  api_post "/api/agent/v1/sensors/$SENSOR_ID/events" \
    "$(jq -n --arg id "$(date +%s)-$$" --arg source "$HOSTNAME" '{batchId:$id,events:[{eventType:"process",source:$source,rawData:{agent:"ats-sensor"},timestamp:(now|todateiso8601)}]}')" >/dev/null
}
heartbeat
send_events
while :; do sleep 30; heartbeat; done
EOF
chmod 700 "$AGENT_SCRIPT"
if [[ "$PLATFORM" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
  cat >/etc/systemd/system/ats-sensor.service <<EOF
[Unit]
Description=SecureNexus sensor agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$AGENT_SCRIPT
Restart=always
RestartSec=10
User=root
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now ats-sensor.service
fi
echo "SecureNexus sensor enrolled successfully."
echo "Credential stored securely in $CONFIG_FILE; the enrollment token was not retained."
