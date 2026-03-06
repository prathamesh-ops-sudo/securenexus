#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# SecureNexus — Self-Hosted GitHub Actions Runner Setup
# ============================================================================
# Run this script on a fresh Ubuntu 22.04+ EC2 instance (t3.medium+ recommended)
# to configure it as a GitHub Actions self-hosted runner.
#
# Prerequisites:
#   - Ubuntu 22.04 LTS (arm64 or x86_64)
#   - Root or sudo access
#   - Internet access
#   - A GitHub runner registration token (from repo Settings > Actions > Runners)
#
# Usage:
#   chmod +x runner-setup.sh
#   sudo ./runner-setup.sh --token <RUNNER_TOKEN> --repo <owner/repo>
#
# Example:
#   sudo ./runner-setup.sh --token AXXXXXX... --repo prathamesh-ops-sudo/securenexus
# ============================================================================

RUNNER_VERSION="2.321.0"
NODE_MAJOR=20
RUNNER_USER="runner"
RUNNER_HOME="/opt/actions-runner"

usage() {
  echo "Usage: $0 --token <GITHUB_RUNNER_TOKEN> --repo <owner/repo> [--labels <label1,label2>]"
  exit 1
}

TOKEN=""
REPO=""
LABELS="self-hosted,Linux,X64,securenexus"

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN="$2"; shift 2;;
    --repo) REPO="$2"; shift 2;;
    --labels) LABELS="$2"; shift 2;;
    *) usage;;
  esac
done

[[ -z "$TOKEN" || -z "$REPO" ]] && usage

echo "========================================"
echo " SecureNexus Runner Setup"
echo " Repo: $REPO"
echo " Labels: $LABELS"
echo "========================================"

# ── 1. System packages ──────────────────────────────────────────────────────
echo "[1/8] Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
  curl wget git jq unzip gnupg lsb-release \
  build-essential ca-certificates \
  libicu-dev libssl-dev libkrb5-dev \
  apt-transport-https software-properties-common

# ── 2. Docker ────────────────────────────────────────────────────────────────
echo "[2/8] Installing Docker..."
if ! command -v docker &>/dev/null; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable docker
systemctl start docker

# ── 3. Node.js ───────────────────────────────────────────────────────────────
echo "[3/8] Installing Node.js ${NODE_MAJOR}..."
if ! command -v node &>/dev/null || [[ "$(node -v | cut -d. -f1 | tr -d v)" != "$NODE_MAJOR" ]]; then
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y -qq nodejs
fi
echo "  Node: $(node -v)  npm: $(npm -v)"

# ── 4. AWS CLI v2 ───────────────────────────────────────────────────────────
echo "[4/8] Installing AWS CLI v2..."
if ! command -v aws &>/dev/null; then
  ARCH=$(uname -m)
  if [[ "$ARCH" == "aarch64" ]]; then
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip
  else
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  fi
  unzip -qo /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
fi
echo "  AWS CLI: $(aws --version)"

# ── 5. kubectl ───────────────────────────────────────────────────────────────
echo "[5/8] Installing kubectl..."
if ! command -v kubectl &>/dev/null; then
  curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/$(dpkg --print-architecture)/kubectl" \
    -o /usr/local/bin/kubectl
  chmod +x /usr/local/bin/kubectl
fi
echo "  kubectl: $(kubectl version --client --short 2>/dev/null || kubectl version --client)"

# ── 6. GitHub CLI ────────────────────────────────────────────────────────────
echo "[6/8] Installing GitHub CLI..."
if ! command -v gh &>/dev/null; then
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list
  apt-get update -qq
  apt-get install -y -qq gh
fi
echo "  gh: $(gh --version | head -1)"

# ── 7. Create runner user and install runner ─────────────────────────────────
echo "[7/8] Setting up GitHub Actions runner..."
id -u "$RUNNER_USER" &>/dev/null || useradd -m -s /bin/bash "$RUNNER_USER"
usermod -aG docker "$RUNNER_USER"
mkdir -p "$RUNNER_HOME"
chown -R "$RUNNER_USER":"$RUNNER_USER" "$RUNNER_HOME"

ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
  RUNNER_ARCH="x64"
elif [[ "$ARCH" == "aarch64" ]]; then
  RUNNER_ARCH="arm64"
else
  echo "Unsupported architecture: $ARCH"
  exit 1
fi

cd "$RUNNER_HOME"
if [[ ! -f ./config.sh ]]; then
  TARBALL="actions-runner-linux-${RUNNER_ARCH}-${RUNNER_VERSION}.tar.gz"
  curl -fsSL "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${TARBALL}" -o "/tmp/${TARBALL}"
  tar xzf "/tmp/${TARBALL}" -C "$RUNNER_HOME"
  chown -R "$RUNNER_USER":"$RUNNER_USER" "$RUNNER_HOME"
  rm -f "/tmp/${TARBALL}"
fi

# Configure the runner
su - "$RUNNER_USER" -c "cd $RUNNER_HOME && RUNNER_TOKEN='${TOKEN}' ./config.sh --url https://github.com/${REPO} --token \"\$RUNNER_TOKEN\" --labels ${LABELS} --name securenexus-runner --work _work --replace --unattended"

# ── 8. Install as a service ──────────────────────────────────────────────────
echo "[8/8] Installing runner as systemd service..."
cd "$RUNNER_HOME"
./svc.sh install "$RUNNER_USER"
./svc.sh start

echo ""
echo "========================================"
echo " Runner setup complete!"
echo " Status: $(./svc.sh status 2>&1 | tail -1)"
echo " Labels: $LABELS"
echo " Home:   $RUNNER_HOME"
echo "========================================"
echo ""
echo "Verify at: https://github.com/${REPO}/settings/actions/runners"
