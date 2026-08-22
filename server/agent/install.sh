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
SERVICE_NAME="ats-sensor"

case "$(uname -s)" in
  Linux) PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *) echo "ERROR: unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

for command_name in curl jq hostname; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: $command_name is required; install it and rerun." >&2
    exit 1
  fi
done

HOSTNAME_VALUE="$(hostname)"
PAYLOAD="$(jq -n \
  --arg token "$ENROLLMENT_TOKEN" \
  --arg hostname "$HOSTNAME_VALUE" \
  --arg platform "$PLATFORM" \
  --arg os "$(uname -sr)" \
  --arg version "$AGENT_VERSION" \
  '{enrollmentToken:$token,hostname:$hostname,platform:$platform,osVersion:$os,agentVersion:$version}')"
RESPONSE="$(curl --fail-with-body --silent --show-error --max-time 30 -X POST \
  "$SERVER_URL/api/agent/v1/enroll" \
  -H "Content-Type: application/json" \
  --data "$PAYLOAD")"
SENSOR_ID="$(jq -er '.data.sensorId' <<<"$RESPONSE")"
API_KEY="$(jq -er '.data.apiKey' <<<"$RESPONSE")"
[[ "$API_KEY" == snx_agent_* ]] || {
  echo "ERROR: enrollment returned no sensor credential." >&2
  exit 1
}

umask 077
install -d -m 700 "$INSTALL_DIR" "$LOG_DIR"
cat >"$CONFIG_FILE" <<EOF
SENSOR_ID=$(printf '%q' "$SENSOR_ID")
API_KEY=$(printf '%q' "$API_KEY")
SERVER_URL=$(printf '%q' "$SERVER_URL")
AGENT_VERSION=$(printf '%q' "$AGENT_VERSION")
PLATFORM=$(printf '%q' "$PLATFORM")
LOG_FILE=$(printf '%q' "$LOG_DIR/agent.log")
PACKAGE_SENT_FILE=$(printf '%q' "$INSTALL_DIR/package-inventory.sent")
EOF
chmod 600 "$CONFIG_FILE"

cat >"$AGENT_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

source /opt/ats-sensor/config.env
: "${SENSOR_ID:?}"
: "${API_KEY:?}"
: "${SERVER_URL:?}"
HOSTNAME_VALUE="$(hostname)"
EVENTS="[]"
PACKAGE_SENT_FILE="${PACKAGE_SENT_FILE:-/opt/ats-sensor/package-inventory.sent}"

log() {
  printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" | tee -a "$LOG_FILE"
}

api_post() {
  local path="$1"
  local body
  if [[ "$#" -ge 2 ]]; then
    body="$2"
  else
    body="$(cat)"
  fi
  curl --fail-with-body --silent --show-error --max-time 30 -X POST \
    "$SERVER_URL$path" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    --data "$body"
}

get_cpu_usage() {
  [[ "$PLATFORM" == "linux" && -r /proc/stat ]] || return 0
  local first second
  first="$(awk '$1 == "cpu" {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat)"
  sleep 1
  second="$(awk '$1 == "cpu" {print $2, $3, $4, $5, $6, $7, $8}' /proc/stat)"
  awk -v first="$first" -v second="$second" '
    BEGIN {
      split(first, a); split(second, b);
      total1 = a[1]+a[2]+a[3]+a[4]+a[5]+a[6]+a[7];
      total2 = b[1]+b[2]+b[3]+b[4]+b[5]+b[6]+b[7];
      idle1 = a[4]+a[5]; idle2 = b[4]+b[5];
      if (total2 > total1) printf "%.1f", (1 - (idle2-idle1)/(total2-total1))*100;
    }'
}

get_memory_usage() {
  [[ "$PLATFORM" == "linux" && -r /proc/meminfo ]] || return 0
  awk '
    /^MemTotal:/ { total = $2 }
    /^MemAvailable:/ { available = $2 }
    END { if (total > 0) printf "%.1f", (total-available)*100/total }' /proc/meminfo
}

get_disk_usage() {
  df -P / 2>/dev/null | awk 'NR == 2 { gsub(/%/, "", $5); if ($5 ~ /^[0-9]+([.][0-9]+)?$/) print $5 }'
}

get_ip_address() {
  if command -v ip >/dev/null 2>&1; then
    local route_ip
    route_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i == "src") { print $(i+1); exit } }')"
    [[ -n "$route_ip" ]] && { printf '%s' "$route_ip"; return; }
  fi
  hostname -I 2>/dev/null | awk '{ for (i=1; i<=NF; i++) if ($i !~ /^127[.]/) { print $i; exit } }'
}

heartbeat() {
  local cpu memory disk ip
  cpu="$(get_cpu_usage)"
  memory="$(get_memory_usage)"
  disk="$(get_disk_usage)"
  ip="$(get_ip_address)"
  jq -n \
    --arg version "$AGENT_VERSION" \
    --arg cpu "$cpu" \
    --arg memory "$memory" \
    --arg disk "$disk" \
    --arg ip "$ip" \
    '{
      agentVersion: $version
    } |
    if $cpu != "" then .cpuUsage = ($cpu|tonumber) else . end |
    if $memory != "" then .memoryUsage = ($memory|tonumber) else . end |
    if $disk != "" then .diskUsage = ($disk|tonumber) else . end |
    if $ip != "" then .ipAddress = $ip else . end' |
    api_post "/api/agent/v1/sensors/$SENSOR_ID/heartbeat" >/dev/null
}

add_event() {
  EVENTS="$(jq --argjson event "$1" '. + [$event]' <<<"$EVENTS")"
}

collect_process_events() {
  command -v ps >/dev/null 2>&1 || return 0
  while read -r pid ppid user process_name process_args; do
    [[ "$pid" =~ ^[0-9]+$ && -n "$process_name" ]] || continue
    add_event "$(jq -n \
      --arg processName "$process_name" \
      --arg processPath "$process_name" \
      --arg processArgs "$process_args" \
      --arg userName "$user" \
      --argjson pid "$pid" \
      --argjson ppid "${ppid:-0}" \
      --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      '{
        eventType:"process",
        processName:$processName,
        processPath:$processPath,
        processArgs:$processArgs,
        pid:$pid,
        ppid:$ppid,
        userName:$userName,
        timestamp:$timestamp
      }')"
  done < <(ps -eo pid=,ppid=,user=,comm=,args= 2>/dev/null | awk 'NR <= 200')
}

collect_network_events() {
  command -v ss >/dev/null 2>&1 || return 0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    add_event "$(jq -n \
      --arg line "$line" \
      --arg source "$HOSTNAME_VALUE" \
      --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      '{
        eventType:"network",
        logSource:"ss",
        logMessage:$line,
        rawData:{source:$source,line:$line},
        timestamp:$timestamp
      }')"
  done < <(ss -H -tunap 2>/dev/null | awk 'NR <= 100')
}

collect_auth_events() {
  local auth_log
  for auth_log in /var/log/auth.log /var/log/secure; do
    [[ -r "$auth_log" ]] || continue
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      add_event "$(jq -n \
        --arg line "$line" \
        --arg source "$auth_log" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
          eventType:"auth",
          authAction:"log",
          authResult:"observed",
          logSource:$source,
          logMessage:$line,
          rawData:{line:$line},
          timestamp:$timestamp
        }')"
    done < <(tail -n 20 "$auth_log")
  done
}

collect_file_events() {
  local file_path file_hash file_size
  for file_path in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab /root/.ssh/authorized_keys /etc/hosts; do
    [[ -r "$file_path" ]] || continue
    if command -v sha256sum >/dev/null 2>&1; then
      file_hash="$(sha256sum "$file_path" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      file_hash="$(shasum -a 256 "$file_path" | awk '{print $1}')"
    else
      continue
    fi
    file_size="$(wc -c <"$file_path" | tr -d ' ')"
    add_event "$(jq -n \
      --arg path "$file_path" \
      --arg hash "$file_hash" \
      --arg size "$file_size" \
      --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      '{
        eventType:"file",
        filePath:$path,
        fileAction:"snapshot",
        fileHash:$hash,
        fileSize:($size|tonumber),
        timestamp:$timestamp
      }')"
  done
}

send_events() {
  local count payload batch_id
  count="$(jq 'length' <<<"$EVENTS")"
  [[ "$count" -gt 0 ]] || return 0
  batch_id="sensor-$(date +%s)-$$"
  payload="$(jq -n --arg batchId "$batch_id" --argjson events "$EVENTS" '{batchId:$batchId,events:$events}')"
  api_post "/api/agent/v1/sensors/$SENSOR_ID/events" "$payload" >/dev/null
  EVENTS="[]"
  log "INFO" "Sent $count observed events"
}

send_package_inventory() {
  local packages="[]" line name version manager now last_sent
  now="$(date +%s)"
  last_sent=0
  if [[ -r "$PACKAGE_SENT_FILE" ]]; then
    read -r last_sent <"$PACKAGE_SENT_FILE"
  fi
  [[ "$now" -ge "$((last_sent + 21600))" ]] || return 0
  if [[ "$PLATFORM" == "linux" && -x "$(command -v dpkg-query 2>/dev/null)" ]]; then
    while IFS=$'\t' read -r name version; do
      [[ -n "$name" && -n "$version" ]] || continue
      packages="$(jq --arg manager "apt" --arg name "$name" --arg version "$version" '. + [{packageManager:$manager,packageName:$name,installedVersion:$version,source:"dpkg-query"}]' <<<"$packages")"
    done < <(dpkg-query -W -f='${binary:Package}\t${Version}\n')
  fi
  if [[ "$PLATFORM" == "linux" && -x "$(command -v rpm 2>/dev/null)" ]]; then
    while IFS=$'\t' read -r name version; do
      [[ -n "$name" && -n "$version" ]] || continue
      packages="$(jq --arg manager "rpm" --arg name "$name" --arg version "$version" '. + [{packageManager:$manager,packageName:$name,installedVersion:$version,source:"rpm"}]' <<<"$packages")"
    done < <(rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n')
  fi
  if [[ "$PLATFORM" == "linux" && -x "$(command -v apk 2>/dev/null)" ]]; then
    while IFS= read -r line; do
      name="${line%%-*}"; version="${line#"$name"-}"
      [[ -n "$name" && -n "$version" ]] || continue
      packages="$(jq --arg manager "apk" --arg name "$name" --arg version "$version" '. + [{packageManager:$manager,packageName:$name,installedVersion:$version,source:"apk"}]' <<<"$packages")"
    done < <(apk info 2>/dev/null)
  fi
  if [[ "$PLATFORM" == "macos" && -x "$(command -v brew 2>/dev/null)" ]]; then
    while IFS=$'\t' read -r name version; do
      [[ -n "$name" && -n "$version" ]] || continue
      packages="$(jq --arg manager "brew" --arg name "$name" --arg version "$version" '. + [{packageManager:$manager,packageName:$name,installedVersion:$version,source:"brew"}]' <<<"$packages")"
    done < <(brew list --versions)
  fi
  if [[ "$(jq 'length' <<<"$packages")" -gt 0 ]]; then
    api_post "/api/agent/v1/sensors/$SENSOR_ID/packages" "$(jq -n --arg batchId "packages-$(date +%s)-$$" --argjson packages "$packages" '{batchId:$batchId,packages:$packages}')" >/dev/null
    printf '%s\n' "$now" >"$PACKAGE_SENT_FILE"
    log "INFO" "Sent $(jq 'length' <<<"$packages") observed packages"
  fi
}

while :; do
  heartbeat
  collect_process_events
  collect_network_events
  collect_auth_events
  collect_file_events
  send_events
  send_package_inventory
  sleep 30
done
EOF
chmod 700 "$AGENT_SCRIPT"

if [[ "$PLATFORM" == "linux" && -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
  cat >/etc/systemd/system/${SERVICE_NAME}.service <<EOF
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
  systemctl enable --now "${SERVICE_NAME}.service"
elif [[ "$PLATFORM" == "macos" && -x /bin/launchctl ]]; then
  cat >/Library/LaunchDaemons/io.securenexus.ats-sensor.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.securenexus.ats-sensor</string>
<key>ProgramArguments</key><array><string>$AGENT_SCRIPT</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
EOF
  launchctl bootstrap system /Library/LaunchDaemons/io.securenexus.ats-sensor.plist
else
  nohup "$AGENT_SCRIPT" >>"$LOG_DIR/agent.log" 2>&1 &
  echo "$!" >"$INSTALL_DIR/agent.pid"
  chmod 600 "$INSTALL_DIR/agent.pid"
fi

echo "SecureNexus sensor enrolled and collecting observed process, network, and authentication telemetry."
echo "Credential stored securely in $CONFIG_FILE; the enrollment token was not retained."
