#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[dev-setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[dev-setup]${NC} $*"; }
error() { echo -e "${RED}[dev-setup]${NC} $*" >&2; }

check_prereqs() {
  local missing=()
  command -v node  >/dev/null 2>&1 || missing+=("node (v20+)")
  command -v npm   >/dev/null 2>&1 || missing+=("npm")
  command -v docker >/dev/null 2>&1 || missing+=("docker")

  if [ ${#missing[@]} -gt 0 ]; then
    error "Missing prerequisites: ${missing[*]}"
    error "Install them and re-run this script."
    exit 1
  fi

  NODE_MAJOR=$(node -v | cut -d. -f1 | tr -d 'v')
  if [ "$NODE_MAJOR" -lt 20 ]; then
    error "Node.js v20+ required (found $(node -v))"
    exit 1
  fi
}

setup_env() {
  if [ ! -f .env ]; then
    info "Creating .env from .env.example"
    cp .env.example .env
  else
    info ".env already exists — skipping"
  fi
}

start_services() {
  info "Starting PostgreSQL and LocalStack via docker-compose"
  docker compose up -d --wait 2>/dev/null || docker-compose up -d 2>/dev/null
  info "Waiting for PostgreSQL to be ready..."
  for i in $(seq 1 30); do
    if docker compose exec -T db pg_isready -U securenexus >/dev/null 2>&1; then
      info "PostgreSQL is ready"
      return 0
    fi
    sleep 1
  done
  error "PostgreSQL did not become ready within 30s"
  exit 1
}

install_deps() {
  info "Installing npm dependencies"
  npm ci
}

run_migrations() {
  info "Pushing database schema via drizzle-kit"
  npx drizzle-kit push 2>&1 || warn "drizzle-kit push failed — database may already be up to date"
}

seed_notice() {
  info "Database seeding runs automatically on first server start."
}

print_summary() {
  echo ""
  info "========================================="
  info "  Dev environment ready!"
  info "========================================="
  info ""
  info "  Start the dev server:  npm run dev"
  info "  Run all checks:        npm run checks"
  info "  Run unit tests:        npm test"
  info "  Run typecheck:         npm run typecheck"
  info ""
  info "  PostgreSQL:  localhost:5432"
  info "  LocalStack:  localhost:4566"
  info "  App:         http://localhost:5000"
  info ""
}

main() {
  info "Setting up SecureNexus development environment"
  echo ""
  check_prereqs
  setup_env
  start_services
  install_deps
  run_migrations
  seed_notice
  print_summary
}

main "$@"
