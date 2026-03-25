#!/usr/bin/env bash
# =============================================================================
# ATS Sensor Agent — Install Script (Linux / macOS)
# Arica Tech Solutions — SecureNexus Platform
#
# Usage:
#   curl -fsSL https://your-server/api/native-sensors/agent/install.sh | \
#     SENSOR_ID="..." API_KEY="..." SERVER_URL="..." bash
# =============================================================================

set -euo pipefail

# ── Validation ──────────────────────────────────────────────────────────────

if [ -z "${SENSOR_ID:-}" ] || [ -z "${API_KEY:-}" ] || [ -z "${SERVER_URL:-}" ]; then
  echo "ERROR: SENSOR_ID, API_KEY, and SERVER_URL environment variables are required."
  echo ""
  echo "Usage:"
  echo "  SENSOR_ID=\"<id>\" API_KEY=\"<key>\" SERVER_URL=\"https://your-server\" bash install.sh"
  exit 1
fi

AGENT_VERSION="1.0.0"
INSTALL_DIR="/opt/ats-sensor"
LOG_DIR="/var/log/ats-sensor"
CONFIG_FILE="$INSTALL_DIR/config.env"
AGENT_SCRIPT="$INSTALL_DIR/ats-agent.sh"
SERVICE_NAME="ats-sensor"

echo "============================================"
echo " ATS Sensor Agent Installer v${AGENT_VERSION}"
echo " Arica Tech Solutions"
echo "============================================"
echo ""
echo "Server URL:  $SERVER_URL"
echo "Sensor ID:   $SENSOR_ID"
echo "Install Dir: $INSTALL_DIR"
echo ""

# ── Root check ──────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root (use sudo)."
  exit 1
fi

# ── Detect OS ───────────────────────────────────────────────────────────────

OS="$(uname -s)"
case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *)      echo "ERROR: Unsupported OS: $OS"; exit 1 ;;
esac

echo "[1/5] Detected platform: $PLATFORM ($OS)"

# ── Install dependencies ───────────────────────────────────────────────────

echo "[2/5] Checking dependencies..."

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

if ! check_cmd curl; then
  echo "  Installing curl..."
  if [ "$PLATFORM" = "linux" ]; then
    apt-get update -qq && apt-get install -y -qq curl 2>/dev/null || \
    yum install -y -q curl 2>/dev/null || \
    apk add --no-cache curl 2>/dev/null || true
  fi
fi

if ! check_cmd jq; then
  echo "  Installing jq..."
  if [ "$PLATFORM" = "linux" ]; then
    apt-get install -y -qq jq 2>/dev/null || \
    yum install -y -q jq 2>/dev/null || \
    apk add --no-cache jq 2>/dev/null || true
  elif [ "$PLATFORM" = "macos" ]; then
    brew install jq 2>/dev/null || true
  fi
fi

# ── Create directories ─────────────────────────────────────────────────────

echo "[3/5] Creating directories..."
mkdir -p "$INSTALL_DIR" "$LOG_DIR"

# ── Write config ────────────────────────────────────────────────────────────

echo "[4/5] Writing configuration..."
cat > "$CONFIG_FILE" <<ENVEOF
# ATS Sensor Agent Configuration
SENSOR_ID="${SENSOR_ID}"
API_KEY="${API_KEY}"
SERVER_URL="${SERVER_URL}"
AGENT_VERSION="${AGENT_VERSION}"
HEARTBEAT_INTERVAL=30
EVENT_BATCH_SIZE=100
EVENT_FLUSH_INTERVAL=10
LOG_FILE="${LOG_DIR}/agent.log"
PLATFORM="${PLATFORM}"
ENVEOF

chmod 600 "$CONFIG_FILE"

# ── Write agent script ─────────────────────────────────────────────────────

cat > "$AGENT_SCRIPT" <<'AGENTEOF'
#!/usr/bin/env bash
# =============================================================================
# ATS Sensor Agent — Daemon
# Collects security events and sends them to the SecureNexus platform
# =============================================================================

set -euo pipefail

# Load config
CONFIG_FILE="/opt/ats-sensor/config.env"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "ERROR: Config file not found: $CONFIG_FILE"
  exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG_FILE"

LOG_FILE="${LOG_FILE:-/var/log/ats-sensor/agent.log}"
HEARTBEAT_INTERVAL="${HEARTBEAT_INTERVAL:-30}"
EVENT_BATCH_SIZE="${EVENT_BATCH_SIZE:-100}"
EVENT_FLUSH_INTERVAL="${EVENT_FLUSH_INTERVAL:-10}"

# ── Logging ─────────────────────────────────────────────────────────────────

log() {
  local level="$1"; shift
  echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') [$level] $*" | tee -a "$LOG_FILE"
}

# ── API helpers ─────────────────────────────────────────────────────────────

api_post() {
  local path="$1"
  local data="$2"
  curl -sS -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Cookie: connect.sid=agent-${SENSOR_ID}" \
    --max-time 15 \
    "${SERVER_URL}${path}" \
    -d "$data" 2>>"$LOG_FILE"
}

api_get() {
  local path="$1"
  curl -sS -X GET \
    -H "Authorization: Bearer ${API_KEY}" \
    -H "Cookie: connect.sid=agent-${SENSOR_ID}" \
    --max-time 10 \
    "${SERVER_URL}${path}" 2>>"$LOG_FILE"
}

# ── System metrics ──────────────────────────────────────────────────────────

get_cpu_usage() {
  if [ "$PLATFORM" = "linux" ]; then
    # Two-sample delta measurement for current CPU usage (not cumulative average)
    local cpu1 cpu2
    cpu1=$(grep 'cpu ' /proc/stat)
    sleep 1
    cpu2=$(grep 'cpu ' /proc/stat)
    echo "$cpu1
$cpu2" | awk 'NR==1{u1=$2+$4; t1=$2+$4+$5} NR==2{u2=$2+$4; t2=$2+$4+$5; if(t2-t1>0) printf "%.1f", (u2-u1)*100/(t2-t1); else printf "0.0"}'
  elif [ "$PLATFORM" = "macos" ]; then
    top -l 1 -n 0 2>/dev/null | awk '/CPU usage/ {print $3}' | tr -d '%' || echo "0"
  fi
}

get_memory_usage() {
  if [ "$PLATFORM" = "linux" ]; then
    free | awk '/Mem:/ {printf "%.1f", ($3/$2)*100}'
  elif [ "$PLATFORM" = "macos" ]; then
    vm_stat 2>/dev/null | awk '/Pages active/ {gsub(/\./,"",$3); active=$3} /Pages wired/ {gsub(/\./,"",$3); wired=$3} /Pages free/ {gsub(/\./,"",$3); free=$3} END {printf "%.1f", (active+wired)/(active+wired+free)*100}' || echo "0"
  fi
}

get_disk_usage() {
  df / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%'
}

# ── Event collectors ────────────────────────────────────────────────────────

EVENT_BUFFER="[]"

add_event() {
  local event_json="$1"
  EVENT_BUFFER=$(echo "$EVENT_BUFFER" | jq --argjson evt "$event_json" '. + [$evt]')
}

flush_events() {
  local count
  count=$(echo "$EVENT_BUFFER" | jq 'length')
  if [ "$count" -eq 0 ]; then
    return
  fi

  log "INFO" "Flushing $count events to server..."
  local payload
  payload=$(jq -n --argjson events "$EVENT_BUFFER" '{"events": $events}')

  local result
  result=$(api_post "/api/native-sensors/${SENSOR_ID}/events" "$payload" || echo '{"error":"failed"}')

  if echo "$result" | jq -e '.accepted' >/dev/null 2>&1; then
    local accepted
    accepted=$(echo "$result" | jq '.accepted')
    local alerts
    alerts=$(echo "$result" | jq '.alertsCreated // 0')
    log "INFO" "Events accepted: $accepted, alerts created: $alerts"
    EVENT_BUFFER="[]"
  else
    log "WARN" "Event flush failed (retaining buffer): $result"
  fi
}

# ── Process monitoring ──────────────────────────────────────────────────────

KNOWN_PIDS=""

collect_process_events() {
  local current_pids
  if [ "$PLATFORM" = "linux" ]; then
    current_pids=$(ps -eo pid,ppid,user,comm,args --no-headers 2>/dev/null || true)
  else
    current_pids=$(ps -eo pid,ppid,user,comm 2>/dev/null || true)
  fi

  # Detect new processes
  while IFS= read -r line; do
    local pid ppid user comm args
    pid=$(echo "$line" | awk '{print $1}')
    ppid=$(echo "$line" | awk '{print $2}')
    user=$(echo "$line" | awk '{print $3}')
    comm=$(echo "$line" | awk '{print $4}')
    args=$(echo "$line" | awk '{for(i=5;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')

    # Skip kernel threads and self
    [ -z "$pid" ] && continue
    [ "$pid" = "PID" ] && continue
    [ "$pid" = "$$" ] && continue

    # Check for suspicious processes
    local suspicious=false
    case "$comm" in
      nc|ncat|netcat|socat) suspicious=true ;;
      wget|curl) # downloading in background could be suspicious
        if echo "$args" | grep -qiE '(tmp|dev/shm|/var/tmp)'; then suspicious=true; fi ;;
      python*|perl|ruby|bash|sh)
        if echo "$args" | grep -qiE '(reverse|shell|bind|socket|connect)'; then suspicious=true; fi ;;
      nmap|masscan|sqlmap|hydra|john|hashcat) suspicious=true ;;
      base64|xxd|openssl)
        if echo "$args" | grep -qiE '(enc|dec|passwd|shadow)'; then suspicious=true; fi ;;
    esac

    if [ "$suspicious" = "true" ] || ! echo "$KNOWN_PIDS" | grep -qw "$pid"; then
      local event
      event=$(jq -n \
        --arg eventType "process_start" \
        --arg processName "$comm" \
        --arg processPath "$comm" \
        --arg processArgs "$args" \
        --argjson pid "$pid" \
        --argjson ppid "${ppid:-0}" \
        --arg userName "$user" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
          eventType: $eventType,
          processName: $processName,
          processPath: $processPath,
          processArgs: $processArgs,
          pid: $pid,
          ppid: $ppid,
          userName: $userName,
          timestamp: $timestamp
        }')
      add_event "$event"
    fi
  done <<< "$current_pids"

  KNOWN_PIDS=$(echo "$current_pids" | awk '{print $1}' | tr '\n' ' ')
}

# ── Network monitoring ──────────────────────────────────────────────────────

collect_network_events() {
  local connections
  if [ "$PLATFORM" = "linux" ]; then
    connections=$(ss -tunapH 2>/dev/null | head -50 || netstat -tunaW 2>/dev/null | tail -n +3 | head -50 || true)
  else
    connections=$(netstat -an -f inet 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | head -50 || true)
  fi

  while IFS= read -r line; do
    [ -z "$line" ] && continue

    local proto src_addr src_port dst_addr dst_port state
    if [ "$PLATFORM" = "linux" ]; then
      proto=$(echo "$line" | awk '{print $1}')
      local src dst
      src=$(echo "$line" | awk '{print $5}')
      dst=$(echo "$line" | awk '{print $6}')
      src_addr=$(echo "$src" | rev | cut -d: -f2- | rev)
      src_port=$(echo "$src" | rev | cut -d: -f1 | rev)
      dst_addr=$(echo "$dst" | rev | cut -d: -f2- | rev)
      dst_port=$(echo "$dst" | rev | cut -d: -f1 | rev)
      state=$(echo "$line" | awk '{print $2}')
    else
      proto=$(echo "$line" | awk '{print $1}')
      local src dst
      src=$(echo "$line" | awk '{print $4}')
      dst=$(echo "$line" | awk '{print $5}')
      src_addr=$(echo "$src" | rev | cut -d. -f2- | rev)
      src_port=$(echo "$src" | rev | cut -d. -f1 | rev)
      dst_addr=$(echo "$dst" | rev | cut -d. -f2- | rev)
      dst_port=$(echo "$dst" | rev | cut -d. -f1 | rev)
      state=$(echo "$line" | awk '{print $6}')
    fi

    # Only report established outbound connections and suspicious ports
    [ -z "$dst_port" ] && continue
    # Skip local connections
    case "$dst_addr" in
      127.*|::1|0.0.0.0) continue ;;
    esac

    # Detect suspicious destination ports
    local suspicious=false
    case "$dst_port" in
      4444|5555|6666|1337|31337|8888|9999) suspicious=true ;; # Common backdoor ports
      *) ;;
    esac

    if [ "$suspicious" = "true" ] || [ "$state" = "ESTAB" ] || [ "$state" = "ESTABLISHED" ]; then
      local event
      event=$(jq -n \
        --arg eventType "network_connection" \
        --arg srcIp "${src_addr:-}" \
        --argjson srcPort "${src_port:-0}" \
        --arg dstIp "${dst_addr:-}" \
        --argjson dstPort "${dst_port:-0}" \
        --arg protocol "${proto:-tcp}" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
          eventType: $eventType,
          srcIp: $srcIp,
          srcPort: $srcPort,
          dstIp: $dstIp,
          dstPort: $dstPort,
          protocol: $protocol,
          timestamp: $timestamp
        }')
      add_event "$event"
    fi
  done <<< "$connections"
}

# ── File monitoring ─────────────────────────────────────────────────────────

WATCHED_PATHS="/etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab /root/.ssh/authorized_keys /etc/hosts"
LAST_FILE_CHECKSUMS=""

collect_file_events() {
  for fpath in $WATCHED_PATHS; do
    [ ! -f "$fpath" ] && continue

    local current_hash
    if check_cmd sha256sum; then
      current_hash=$(sha256sum "$fpath" 2>/dev/null | awk '{print $1}')
    elif check_cmd shasum; then
      current_hash=$(shasum -a 256 "$fpath" 2>/dev/null | awk '{print $1}')
    else
      continue
    fi

    local prev_hash
    prev_hash=$(echo "$LAST_FILE_CHECKSUMS" | grep "^${fpath}:" | cut -d: -f2)

    if [ -n "$prev_hash" ] && [ "$current_hash" != "$prev_hash" ]; then
      local fsize
      fsize=$(stat -c%s "$fpath" 2>/dev/null || stat -f%z "$fpath" 2>/dev/null || echo 0)
      local event
      event=$(jq -n \
        --arg eventType "file_modification" \
        --arg filePath "$fpath" \
        --arg fileAction "modified" \
        --arg fileHash "$current_hash" \
        --argjson fileSize "${fsize:-0}" \
        --arg userName "$(stat -c%U "$fpath" 2>/dev/null || stat -f%Su "$fpath" 2>/dev/null || echo unknown)" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
          eventType: $eventType,
          filePath: $filePath,
          fileAction: $fileAction,
          fileHash: $fileHash,
          fileSize: $fileSize,
          userName: $userName,
          timestamp: $timestamp
        }')
      add_event "$event"
      log "WARN" "Sensitive file modified: $fpath"
    fi

    # Update stored checksum
    LAST_FILE_CHECKSUMS=$(echo "$LAST_FILE_CHECKSUMS" | grep -v "^${fpath}:" || true)
    LAST_FILE_CHECKSUMS="${LAST_FILE_CHECKSUMS}
${fpath}:${current_hash}"
  done

  # Also watch /tmp and /dev/shm for suspicious executables
  for dir in /tmp /dev/shm /var/tmp; do
    [ ! -d "$dir" ] && continue
    while IFS= read -r suspicious_file; do
      [ -z "$suspicious_file" ] && continue
      local event
      event=$(jq -n \
        --arg eventType "file_creation" \
        --arg filePath "$suspicious_file" \
        --arg fileAction "created" \
        --arg logMessage "Executable found in suspicious directory" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
          eventType: $eventType,
          filePath: $filePath,
          fileAction: $fileAction,
          logMessage: $logMessage,
          timestamp: $timestamp
        }')
      add_event "$event"
    done < <(find "$dir" -maxdepth 2 -type f -executable -newer "$LOG_FILE" 2>/dev/null | head -20)
  done
}

# ── Auth monitoring ─────────────────────────────────────────────────────────

LAST_AUTH_LINE=0

collect_auth_events() {
  local auth_log=""
  if [ -f /var/log/auth.log ]; then
    auth_log="/var/log/auth.log"
  elif [ -f /var/log/secure ]; then
    auth_log="/var/log/secure"
  elif [ "$PLATFORM" = "macos" ]; then
    # macOS uses unified logging
    local entries
    entries=$(log show --predicate 'subsystem == "com.apple.securityd" OR category == "authorization"' --last 30s 2>/dev/null | head -20 || true)
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local event
      event=$(jq -n \
        --arg eventType "auth_event" \
        --arg authAction "login" \
        --arg logMessage "$line" \
        --arg logSource "unified_log" \
        --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
          eventType: $eventType,
          authAction: $authAction,
          logMessage: $logMessage,
          logSource: $logSource,
          timestamp: $timestamp
        }')
      add_event "$event"
    done <<< "$entries"
    return
  fi

  [ -z "$auth_log" ] && return
  [ ! -r "$auth_log" ] && return

  local total_lines
  total_lines=$(wc -l < "$auth_log" 2>/dev/null || echo 0)
  [ "$LAST_AUTH_LINE" -ge "$total_lines" ] && LAST_AUTH_LINE=0

  local new_lines
  new_lines=$(tail -n +$((LAST_AUTH_LINE + 1)) "$auth_log" 2>/dev/null | head -100 || true)
  LAST_AUTH_LINE=$total_lines

  while IFS= read -r line; do
    [ -z "$line" ] && continue

    local auth_action="" auth_result="" user_name=""

    # SSH login attempts
    if echo "$line" | grep -qiE 'sshd.*accepted'; then
      auth_action="ssh_login"
      auth_result="success"
      user_name=$(echo "$line" | grep -oP 'for \K\w+' || echo "unknown")
    elif echo "$line" | grep -qiE 'sshd.*(failed|invalid)'; then
      auth_action="ssh_login"
      auth_result="failure"
      user_name=$(echo "$line" | grep -oP 'for (invalid user )?\K\w+' || echo "unknown")
    # sudo
    elif echo "$line" | grep -qiE 'sudo:.*COMMAND'; then
      auth_action="sudo"
      auth_result="success"
      user_name=$(echo "$line" | grep -oP 'sudo:\s+\K\w+' || echo "unknown")
    # su
    elif echo "$line" | grep -qiE 'su\[.*\]'; then
      auth_action="su"
      auth_result=$(echo "$line" | grep -qi 'failed' && echo "failure" || echo "success")
    # PAM
    elif echo "$line" | grep -qiE 'pam_unix.*authentication failure'; then
      auth_action="pam_auth"
      auth_result="failure"
      user_name=$(echo "$line" | grep -oP 'user=\K\w+' || echo "unknown")
    else
      continue
    fi

    local src_ip
    src_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1 || echo "")

    local event
    event=$(jq -n \
      --arg eventType "auth_event" \
      --arg authAction "$auth_action" \
      --arg authResult "$auth_result" \
      --arg authMethod "password" \
      --arg userName "$user_name" \
      --arg srcIp "$src_ip" \
      --arg logMessage "$line" \
      --arg logSource "auth_log" \
      --arg timestamp "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      '{
        eventType: $eventType,
        authAction: $authAction,
        authResult: $authResult,
        authMethod: $authMethod,
        userName: $userName,
        srcIp: $srcIp,
        logMessage: $logMessage,
        logSource: $logSource,
        timestamp: $timestamp
      }')
    add_event "$event"
  done <<< "$new_lines"
}

# ── Response action executor ────────────────────────────────────────────────

poll_and_execute_actions() {
  local result
  result=$(api_get "/api/native-sensors/${SENSOR_ID}/pending-actions" || echo '{"actions":[]}')

  local action_count
  action_count=$(echo "$result" | jq '.actions | length' 2>/dev/null || echo 0)
  [ "$action_count" -eq 0 ] && return

  log "INFO" "Found $action_count pending actions to execute"

  echo "$result" | jq -c '.actions[]' 2>/dev/null | while IFS= read -r action; do
    local action_id action_type target_pid target_ip target_file target_process target_domain target_service
    action_id=$(echo "$action" | jq -r '.id')
    action_type=$(echo "$action" | jq -r '.actionType')

    log "INFO" "Executing action: $action_type (ID: $action_id)"

    local success=false
    local output=""

    case "$action_type" in
      kill_process)
        target_pid=$(echo "$action" | jq -r '.targetPid // empty')
        target_process=$(echo "$action" | jq -r '.targetProcessName // empty')
        if [ -n "$target_pid" ]; then
          output=$(kill -9 "$target_pid" 2>&1 && echo "Process $target_pid killed" || echo "Failed to kill PID $target_pid")
          kill -0 "$target_pid" 2>/dev/null || success=true
        elif [ -n "$target_process" ]; then
          output=$(pkill -9 -f "$target_process" 2>&1 && echo "Process $target_process killed" || echo "Failed to kill $target_process")
          pgrep -f "$target_process" >/dev/null 2>&1 || success=true
        fi
        ;;

      block_ip)
        target_ip=$(echo "$action" | jq -r '.targetIp // empty')
        if [ -n "$target_ip" ]; then
          if check_cmd iptables; then
            output=$(iptables -I INPUT -s "$target_ip" -j DROP 2>&1 && iptables -I OUTPUT -d "$target_ip" -j DROP 2>&1 && echo "IP $target_ip blocked via iptables" || echo "iptables failed")
            success=true
          elif check_cmd pfctl; then
            echo "block drop from $target_ip" | pfctl -a ats-sensor -f - 2>&1
            output="IP $target_ip blocked via pf"
            success=true
          else
            output="No firewall tool available (iptables/pfctl)"
          fi
        fi
        ;;

      quarantine_file)
        target_file=$(echo "$action" | jq -r '.targetFilePath // empty')
        if [ -n "$target_file" ] && [ -f "$target_file" ]; then
          mkdir -p /opt/ats-sensor/quarantine
          local quarantine_path="/opt/ats-sensor/quarantine/$(basename "$target_file").$(date +%s)"
          mv "$target_file" "$quarantine_path" 2>&1
          chmod 000 "$quarantine_path"
          output="File quarantined to $quarantine_path"
          success=true
        else
          output="File not found: $target_file"
        fi
        ;;

      delete_file)
        target_file=$(echo "$action" | jq -r '.targetFilePath // empty')
        if [ -n "$target_file" ] && [ -f "$target_file" ]; then
          rm -f "$target_file" 2>&1
          output="File deleted: $target_file"
          success=true
        else
          output="File not found: $target_file"
        fi
        ;;

      isolate_host)
        if check_cmd iptables; then
          # Allow management channel (the server URL), drop everything else
          local server_host
          server_host=$(echo "$SERVER_URL" | sed -E 's|https?://||' | cut -d: -f1 | cut -d/ -f1)
          # Remove only ATS-ISOLATE rules (preserve existing firewall rules)
          iptables -S 2>/dev/null | grep 'ATS-ISOLATE' | sed 's/^-A/-D/' | while IFS= read -r rule; do
            eval "iptables $rule" 2>/dev/null || true
          done
          iptables -A INPUT -s "$server_host" -j ACCEPT -m comment --comment "ATS-ISOLATE"
          iptables -A OUTPUT -d "$server_host" -j ACCEPT -m comment --comment "ATS-ISOLATE"
          iptables -A INPUT -i lo -j ACCEPT -m comment --comment "ATS-ISOLATE"
          iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment "ATS-ISOLATE"
          # Allow DNS so the agent can keep resolving the server hostname
          for dns_ip in $(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'); do
            iptables -A OUTPUT -d "$dns_ip" -p udp --dport 53 -j ACCEPT -m comment --comment "ATS-ISOLATE"
            iptables -A INPUT -s "$dns_ip" -p udp --sport 53 -j ACCEPT -m comment --comment "ATS-ISOLATE"
            iptables -A OUTPUT -d "$dns_ip" -p tcp --dport 53 -j ACCEPT -m comment --comment "ATS-ISOLATE"
            iptables -A INPUT -s "$dns_ip" -p tcp --sport 53 -j ACCEPT -m comment --comment "ATS-ISOLATE"
          done
          iptables -A INPUT -j DROP -m comment --comment "ATS-ISOLATE"
          iptables -A OUTPUT -j DROP -m comment --comment "ATS-ISOLATE"
          iptables -A FORWARD -j DROP -m comment --comment "ATS-ISOLATE"
          output="Host isolated. Only management channel ($server_host) allowed. Existing rules preserved."
          success=true
        else
          output="iptables not available for host isolation"
        fi
        ;;

      block_domain)
        target_domain=$(echo "$action" | jq -r '.targetDomain // empty')
        if [ -n "$target_domain" ]; then
          echo "127.0.0.1 $target_domain" >> /etc/hosts
          echo "::1 $target_domain" >> /etc/hosts
          output="Domain $target_domain sinkholed via /etc/hosts"
          success=true
        fi
        ;;

      enable_logging)
        if [ "$PLATFORM" = "linux" ]; then
          if check_cmd auditctl; then
            auditctl -e 1 2>&1
            auditctl -a always,exit -F arch=b64 -S execve -k ats-exec 2>&1
            auditctl -w /etc/passwd -p wa -k ats-passwd 2>&1
            auditctl -w /etc/shadow -p wa -k ats-shadow 2>&1
            output="Enhanced audit logging enabled"
            success=true
          else
            output="auditctl not available"
          fi
        fi
        ;;

      restart_service)
        target_service=$(echo "$action" | jq -r '.targetServiceName // empty')
        if [ -n "$target_service" ]; then
          output=$(systemctl restart "$target_service" 2>&1 && echo "Service $target_service restarted" || echo "Failed to restart $target_service")
          systemctl is-active "$target_service" >/dev/null 2>&1 && success=true
        fi
        ;;

      disable_user)
        local target_user
        target_user=$(echo "$action" | jq -r '.targetUserName // empty')
        if [ -n "$target_user" ]; then
          if check_cmd usermod; then
            usermod -L "$target_user" 2>&1
            pkill -u "$target_user" 2>/dev/null || true
            output="User $target_user disabled and sessions terminated"
            success=true
          else
            output="usermod not available"
          fi
        fi
        ;;

      *)
        output="Unknown action type: $action_type"
        ;;
    esac

    # Report result back
    local status_val
    if [ "$success" = "true" ]; then
      status_val="completed"
    else
      status_val="failed"
    fi

    local report_payload
    report_payload=$(jq -n \
      --arg status "$status_val" \
      --arg resultOutput "$output" \
      '{"status": $status, "resultOutput": $resultOutput}')

    api_post "/api/native-sensors/${SENSOR_ID}/action-result/${action_id}" "$report_payload" >/dev/null 2>&1 || true
    log "INFO" "Action $action_id ($action_type) -> $status_val: $output"
  done
}

# ── Main loop ───────────────────────────────────────────────────────────────

main() {
  log "INFO" "ATS Sensor Agent starting (v${AGENT_VERSION})"
  log "INFO" "Server: ${SERVER_URL}, Sensor: ${SENSOR_ID}"

  # Initialize file checksums
  for fpath in $WATCHED_PATHS; do
    [ ! -f "$fpath" ] && continue
    local hash
    if check_cmd sha256sum; then
      hash=$(sha256sum "$fpath" 2>/dev/null | awk '{print $1}')
    elif check_cmd shasum; then
      hash=$(shasum -a 256 "$fpath" 2>/dev/null | awk '{print $1}')
    fi
    LAST_FILE_CHECKSUMS="${LAST_FILE_CHECKSUMS}
${fpath}:${hash}"
  done

  local heartbeat_counter=0
  local event_counter=0
  local action_counter=0

  while true; do
    # Collect events every cycle (10s)
    collect_process_events
    collect_network_events
    collect_auth_events

    event_counter=$((event_counter + 1))

    # File monitoring every 30s
    if [ $((event_counter % 3)) -eq 0 ]; then
      collect_file_events
    fi

    # Flush events every EVENT_FLUSH_INTERVAL seconds
    local buf_size
    buf_size=$(echo "$EVENT_BUFFER" | jq 'length' 2>/dev/null || echo 0)
    local flush_interval_cycles=$(( (EVENT_FLUSH_INTERVAL + 9) / 10 ))
    [ "$flush_interval_cycles" -lt 1 ] && flush_interval_cycles=1
    if [ "$buf_size" -ge "$EVENT_BATCH_SIZE" ] || [ $((event_counter % flush_interval_cycles)) -eq 0 ]; then
      flush_events
    fi

    # Heartbeat every HEARTBEAT_INTERVAL seconds
    heartbeat_counter=$((heartbeat_counter + 10))
    if [ "$heartbeat_counter" -ge "$HEARTBEAT_INTERVAL" ]; then
      heartbeat_counter=0
      local cpu mem disk
      cpu=$(get_cpu_usage)
      mem=$(get_memory_usage)
      disk=$(get_disk_usage)

      local hb_payload
      hb_payload=$(jq -n \
        --argjson cpuUsage "${cpu:-0}" \
        --argjson memoryUsage "${mem:-0}" \
        --argjson diskUsage "${disk:-0}" \
        --arg agentVersion "$AGENT_VERSION" \
        '{"cpuUsage": $cpuUsage, "memoryUsage": $memoryUsage, "diskUsage": $diskUsage, "agentVersion": $agentVersion}')

      api_post "/api/native-sensors/${SENSOR_ID}/heartbeat" "$hb_payload" >/dev/null 2>&1 || \
        log "WARN" "Heartbeat failed"
    fi

    # Poll for response actions every 30s
    action_counter=$((action_counter + 10))
    if [ "$action_counter" -ge 30 ]; then
      action_counter=0
      poll_and_execute_actions || true
    fi

    sleep 10
  done
}

# Trap signals for clean shutdown
trap 'log "INFO" "Agent shutting down..."; flush_events; exit 0' EXIT

main "$@"
AGENTEOF

chmod +x "$AGENT_SCRIPT"

# ── Install systemd service (Linux) or launchd (macOS) ──────────────────────

echo "[5/5] Installing service..."

if [ "$PLATFORM" = "linux" ]; then
  cat > /etc/systemd/system/${SERVICE_NAME}.service <<SVCEOF
[Unit]
Description=ATS Sensor Agent — SecureNexus Security Monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${AGENT_SCRIPT}
Restart=always
RestartSec=10
User=root
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.log
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable ${SERVICE_NAME}
  systemctl start ${SERVICE_NAME}

  echo ""
  echo "============================================"
  echo " Installation Complete!"
  echo "============================================"
  echo ""
  echo "Service: systemctl status ${SERVICE_NAME}"
  echo "Logs:    journalctl -u ${SERVICE_NAME} -f"
  echo "Config:  ${CONFIG_FILE}"
  echo ""

elif [ "$PLATFORM" = "macos" ]; then
  cat > /Library/LaunchDaemons/com.aricatech.ats-sensor.plist <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aricatech.ats-sensor</string>
    <key>ProgramArguments</key>
    <array>
        <string>${AGENT_SCRIPT}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent-error.log</string>
</dict>
</plist>
PLISTEOF

  launchctl load /Library/LaunchDaemons/com.aricatech.ats-sensor.plist

  echo ""
  echo "============================================"
  echo " Installation Complete!"
  echo "============================================"
  echo ""
  echo "Service: sudo launchctl list com.aricatech.ats-sensor"
  echo "Logs:    tail -f ${LOG_DIR}/agent.log"
  echo "Config:  ${CONFIG_FILE}"
  echo ""
fi

echo "Sensor ID: ${SENSOR_ID}"
echo "Server:    ${SERVER_URL}"
echo ""
