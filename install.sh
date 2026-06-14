#!/usr/bin/env bash
# =============================================================================
# Watcher MK1 — Linux Production Installer
# =============================================================================
# Automates the complete production deployment of Watcher MK1 on a fresh
# Ubuntu 22.04+ or Debian 12+ server. Replaces the manual 10-step deployment
# guide with a single-command setup.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# Requirements:
#   - Ubuntu 22.04+ or Debian 12+
#   - User with sudo access (script does not require running as root)
#
# Exit Codes:
#   0 - Success
#   1 - General failure
#   2 - Unsupported operating system
#   3 - Missing sudo privileges
# =============================================================================

set -euo pipefail

# =============================================================================
# Global Variables
# =============================================================================

# Resolve install directory from script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${SCRIPT_DIR}"

# Log directory
LOG_DIR="/var/log/watcher-mk1"

# =============================================================================
# Exit Codes
# =============================================================================

readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EXIT_UNSUPPORTED_OS=2
readonly EXIT_MISSING_SUDO=3

# =============================================================================
# Color Codes
# =============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# =============================================================================
# Utility Functions
# =============================================================================

info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
  echo -e "${GREEN}[OK]${NC} $*"
}

# =============================================================================
# OS Detection
# =============================================================================

check_os() {
  info "Checking operating system compatibility..."

  # Verify we are running on Linux
  if [[ "$(uname -s)" != "Linux" ]]; then
    error "This installer only supports Linux systems."
    error "Detected OS: $(uname -s)"
    exit ${EXIT_UNSUPPORTED_OS}
  fi

  # Check for Ubuntu 22.04+ or Debian 12+
  if [[ ! -f /etc/os-release ]]; then
    error "Cannot determine OS distribution. /etc/os-release not found."
    exit ${EXIT_UNSUPPORTED_OS}
  fi

  # shellcheck source=/dev/null
  source /etc/os-release

  case "${ID}" in
    ubuntu)
      local major_version
      major_version="$(echo "${VERSION_ID}" | cut -d. -f1)"
      if [[ "${major_version}" -lt 22 ]]; then
        error "Ubuntu ${VERSION_ID} is not supported. Minimum required: Ubuntu 22.04"
        exit ${EXIT_UNSUPPORTED_OS}
      fi
      success "Detected Ubuntu ${VERSION_ID}"
      ;;
    debian)
      local major_version
      major_version="$(echo "${VERSION_ID}" | cut -d. -f1)"
      if [[ "${major_version}" -lt 12 ]]; then
        error "Debian ${VERSION_ID} is not supported. Minimum required: Debian 12"
        exit ${EXIT_UNSUPPORTED_OS}
      fi
      success "Detected Debian ${VERSION_ID}"
      ;;
    *)
      error "Unsupported distribution: ${ID}"
      error "Only Ubuntu 22.04+ and Debian 12+ are supported."
      exit ${EXIT_UNSUPPORTED_OS}
      ;;
  esac
}

# =============================================================================
# Sudo Check
# =============================================================================

check_sudo() {
  info "Checking sudo access..."

  if ! command -v sudo &>/dev/null; then
    error "sudo is not installed. This script requires sudo for package installation."
    exit ${EXIT_MISSING_SUDO}
  fi

  if ! sudo -v &>/dev/null; then
    error "This script requires sudo access."
    error "Please run as a user with sudo privileges."
    exit ${EXIT_MISSING_SUDO}
  fi

  success "sudo access confirmed"
}

# =============================================================================
# Database Provisioning
# =============================================================================

# Check if the watcher_mk1 database already exists
db_exists() {
  sudo -u postgres psql -lqt | grep -qw watcher_mk1
}

# Prompt user for database credentials with silent password input
prompt_db_credentials() {
  echo ""
  info "Database credentials required for first-time setup."
  echo ""

  read -rp "  Enter database username: " DB_USER

  while true; do
    read -rsp "  Enter database password: " DB_PASS
    echo ""
    read -rsp "  Confirm database password: " DB_PASS_CONFIRM
    echo ""

    if [[ "${DB_PASS}" == "${DB_PASS_CONFIRM}" ]]; then
      break
    else
      warn "Passwords do not match. Please try again."
    fi
  done

  success "Database credentials captured."
}

# Create a PostgreSQL user with the provided credentials
create_db_user() {
  info "Creating PostgreSQL user '${DB_USER}'..."

  # Use double-quoting in SQL to safely handle special characters in identifiers
  if ! sudo -u postgres psql -c "CREATE USER \"${DB_USER}\" WITH PASSWORD '${DB_PASS//\'/\'\'}';" 2>/dev/null; then
    error "Failed to create PostgreSQL user '${DB_USER}'."
    error "Ensure PostgreSQL is running and the user does not already exist."
    exit ${EXIT_FAILURE}
  fi

  success "PostgreSQL user '${DB_USER}' created."
}

# Create the watcher_mk1 database owned by the specified user
create_database() {
  info "Creating database 'watcher_mk1' owned by '${DB_USER}'..."

  if ! sudo -u postgres psql -c "CREATE DATABASE watcher_mk1 OWNER \"${DB_USER}\";" 2>/dev/null; then
    error "Failed to create database 'watcher_mk1'."
    error "Check PostgreSQL logs for details."
    exit ${EXIT_FAILURE}
  fi

  success "Database 'watcher_mk1' created."
}

# Apply the schema from src/database/schema.sql to the watcher_mk1 database
apply_schema() {
  info "Applying database schema from src/database/schema.sql..."

  if ! PGPASSWORD="${DB_PASS}" psql -U "${DB_USER}" -h localhost -d watcher_mk1 -f "${INSTALL_DIR}/src/database/schema.sql" 2>/dev/null; then
    error "Failed to apply database schema."
    error "Verify that the database is accessible and schema.sql is valid."
    exit ${EXIT_FAILURE}
  fi

  success "Database schema applied successfully."
}

# Orchestrate database provisioning — skip if DB already exists
provision_database() {
  info "Checking for existing database..."

  if db_exists; then
    success "Existing database 'watcher_mk1' detected. Skipping database provisioning."
    # If .env doesn't exist yet we still need credentials for env generation
    if [[ ! -f "${INSTALL_DIR}/.env" && -z "${DB_USER}" ]]; then
      info "Database credentials needed for .env generation."
      prompt_db_credentials
    fi
    return 0
  fi

  info "Database 'watcher_mk1' not found. Proceeding with provisioning..."
  prompt_db_credentials
  create_db_user
  create_database
  apply_schema

  success "Database provisioning complete."
}

# =============================================================================
# Dependency Detection Functions
# =============================================================================

# Check if Node.js is installed at version 20 or higher.
# Returns 0 if present and compatible, 1 if missing or incompatible.
check_node() {
  if ! command -v node &>/dev/null; then
    return 1
  fi

  local version_output
  version_output="$(node --version 2>/dev/null)" || return 1

  # Strip leading 'v' and extract major version (e.g., "v20.11.0" → "20")
  local major
  major="$(echo "${version_output}" | sed 's/^v//' | cut -d. -f1)"

  if [[ -z "${major}" ]] || [[ "${major}" -lt 20 ]]; then
    return 1
  fi

  return 0
}

# Check if PostgreSQL is installed at version 15 or higher.
# Returns 0 if present and compatible, 1 if missing or incompatible.
check_postgres() {
  if ! command -v psql &>/dev/null; then
    return 1
  fi

  local version_output
  version_output="$(psql --version 2>/dev/null)" || return 1

  # Parse major version from output like "psql (PostgreSQL) 15.4"
  local major
  major="$(echo "${version_output}" | grep -oE '[0-9]+' | head -1)"

  if [[ -z "${major}" ]] || [[ "${major}" -lt 15 ]]; then
    return 1
  fi

  return 0
}

# Check if Ollama is installed by verifying the command succeeds.
# Returns 0 if present, 1 if missing.
check_ollama() {
  if ! command -v ollama &>/dev/null; then
    return 1
  fi

  ollama --version &>/dev/null || return 1
  return 0
}

# Check if Supermemory server binary exists.
# Returns 0 if present, 1 if missing.
check_supermemory() {
  # Check if supermemory is available as a command
  if command -v supermemory &>/dev/null; then
    return 0
  fi

  # Check if it's available via npx (installed as npm package)
  if npx --no supermemory --version &>/dev/null 2>&1; then
    return 0
  fi

  return 1
}

# Check if PM2 is globally installed.
# Returns 0 if present, 1 if missing.
check_pm2() {
  if ! command -v pm2 &>/dev/null; then
    return 1
  fi

  pm2 --version &>/dev/null || return 1
  return 0
}

# =============================================================================
# Dependency Installation Functions
# =============================================================================

# Install Node.js 20 via the NodeSource setup script.
# Uses the official NodeSource repository for reliable, up-to-date packages.
install_node() {
  info "Installing Node.js 20 via NodeSource..."

  if ! curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -; then
    error "Failed to add NodeSource repository for Node.js 20."
    error "Check network connectivity and DNS resolution."
    exit ${EXIT_FAILURE}
  fi

  if ! sudo apt-get install -y nodejs; then
    error "Failed to install Node.js from NodeSource repository."
    error "Run 'sudo apt-get update' and try again."
    exit ${EXIT_FAILURE}
  fi

  success "Node.js $(node --version) installed successfully."
}

# Install PostgreSQL via apt package manager.
# Installs both the server and contrib extensions.
install_postgres() {
  info "Installing PostgreSQL via apt..."

  if ! sudo apt-get update -y; then
    error "Failed to update apt package lists."
    exit ${EXIT_FAILURE}
  fi

  if ! sudo apt-get install -y postgresql postgresql-contrib; then
    error "Failed to install PostgreSQL."
    error "Check apt sources and network connectivity."
    exit ${EXIT_FAILURE}
  fi

  success "PostgreSQL $(psql --version | grep -oE '[0-9]+\.[0-9]+' | head -1) installed successfully."
}

# Install Ollama using the official install script.
install_ollama() {
  info "Installing Ollama via official install script..."

  if ! curl -fsSL https://ollama.com/install.sh | sh; then
    error "Failed to install Ollama."
    error "Check network connectivity and try again."
    exit ${EXIT_FAILURE}
  fi

  success "Ollama installed successfully."
}

# Install Supermemory server globally via npm.
install_supermemory() {
  info "Installing Supermemory server via npm..."

  if ! npm install -g @supermemory/server; then
    error "Failed to install Supermemory server."
    error "Ensure Node.js and npm are installed and working correctly."
    exit ${EXIT_FAILURE}
  fi

  success "Supermemory server installed successfully."
}

# Install PM2 process manager globally via npm.
install_pm2() {
  info "Installing PM2 globally via npm..."

  if ! npm install -g pm2; then
    error "Failed to install PM2."
    error "Ensure Node.js and npm are installed and working correctly."
    exit ${EXIT_FAILURE}
  fi

  success "PM2 $(pm2 --version) installed successfully."
}

# =============================================================================
# Dependency Orchestrator
# =============================================================================

# Orchestrate dependency detection and installation.
# Iterates all required dependencies, installs missing ones, skips present ones,
# and prints a summary listing each dependency with its installed version.
install_dependencies() {
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Dependency Detection & Installation"
  info "────────────────────────────────────────────────────────────"
  echo ""

  # Track which dependencies were installed vs already present
  local node_status="missing"
  local postgres_status="missing"
  local ollama_status="missing"
  local supermemory_status="missing"
  local pm2_status="missing"

  # --- Node.js ---
  if check_node; then
    success "Node.js is already installed. Skipping."
    node_status="present"
  else
    info "Node.js not found or incompatible version. Installing..."
    install_node
    node_status="installed"
  fi

  # --- PostgreSQL ---
  if check_postgres; then
    success "PostgreSQL is already installed. Skipping."
    postgres_status="present"
  else
    info "PostgreSQL not found or incompatible version. Installing..."
    install_postgres
    postgres_status="installed"
  fi

  # --- Ollama ---
  if check_ollama; then
    success "Ollama is already installed. Skipping."
    ollama_status="present"
  else
    info "Ollama not found. Installing..."
    install_ollama
    ollama_status="installed"
  fi

  # --- Supermemory ---
  if check_supermemory; then
    success "Supermemory is already installed. Skipping."
    supermemory_status="present"
  else
    info "Supermemory not found. Installing..."
    install_supermemory
    supermemory_status="installed"
  fi

  # --- PM2 ---
  if check_pm2; then
    success "PM2 is already installed. Skipping."
    pm2_status="present"
  else
    info "PM2 not found. Installing..."
    install_pm2
    pm2_status="installed"
  fi

  # --- Summary ---
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Dependency Summary:"
  echo ""

  # Get installed versions for display
  local node_version
  node_version="$(node --version 2>/dev/null || echo 'unknown')"

  local pg_version
  pg_version="$(psql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo 'unknown')"

  local ollama_version
  ollama_version="$(ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'installed')"

  local supermemory_version="installed"

  local pm2_version
  pm2_version="$(pm2 --version 2>/dev/null || echo 'unknown')"

  echo -e "    Node.js ......... ${node_version}"
  echo -e "    PostgreSQL ...... ${pg_version}"
  echo -e "    Ollama .......... ${ollama_version:-installed}"
  echo -e "    Supermemory ..... ${supermemory_version}"
  echo -e "    PM2 ............ v${pm2_version}"
  echo ""
  info "────────────────────────────────────────────────────────────"
  echo ""

  success "All dependencies are installed and ready."
}

# =============================================================================
# Environment Configuration
# =============================================================================

# Replace a key's value in the .env file using sed.
# Handles formats: KEY=value, KEY="value", KEY='value', KEY= (empty)
# Arguments:
#   $1 - Key name
#   $2 - New value
set_env_value() {
  local key="$1"
  local value="$2"
  local env_file="${INSTALL_DIR}/.env"

  # Escape sed special characters in the replacement value: & \ |
  local escaped_value
  escaped_value="$(printf '%s' "${value}" | sed 's/[&\|]/\\&/g')"

  # Replace the line matching KEY=... with KEY=new_value
  # Handles: KEY=value, KEY="value", KEY='value', KEY= (empty value)
  sed -i "s|^${key}=.*|${key}=${escaped_value}|" "${env_file}"
}

# Generate a cryptographically random JWT secret (64 hex characters = 32 bytes)
generate_jwt_secret() {
  openssl rand -hex 32
}

# Generate .env from .env.example template and apply production values.
# Skips entirely if .env already exists, preserving existing configuration.
generate_env() {
  local env_file="${INSTALL_DIR}/.env"
  local env_example="${INSTALL_DIR}/.env.example"

  info "Configuring environment..."

  # Idempotency: skip if .env already exists
  if [[ -f "${env_file}" ]]; then
    warn ".env file already exists. Preserving existing configuration."
    return 0
  fi

  # Verify .env.example exists
  if [[ ! -f "${env_example}" ]]; then
    error ".env.example not found at ${env_example}"
    exit ${EXIT_FAILURE}
  fi

  # Ensure DB credentials are available for .env generation
  if [[ -z "${DB_USER}" || -z "${DB_PASS}" ]]; then
    warn "Database credentials not yet provided. Prompting now for .env configuration."
    prompt_db_credentials
  fi

  # Copy template to .env
  cp "${env_example}" "${env_file}"
  info "Created .env from .env.example template"

  # Generate JWT secret
  local jwt_secret
  jwt_secret="$(generate_jwt_secret)"

  # Apply production values
  set_env_value "NODE_ENV" "production"
  set_env_value "DB_ENABLED" "true"
  set_env_value "DB_USER" "${DB_USER}"
  set_env_value "DB_PASSWORD" "${DB_PASS}"
  set_env_value "JWT_SECRET" "${jwt_secret}"
  set_env_value "AUTH_ENABLED" "true"
  set_env_value "SUPERMEMORY_BASE_URL" "http://localhost:6767"
  set_env_value "SUPERMEMORY_LLM_PROVIDER" "ollama"

  success "Environment configured with production values"
}

# =============================================================================
# Application Build
# =============================================================================

# Build the backend: install dependencies and compile TypeScript.
# Runs in a subshell to avoid changing the parent shell's working directory.
build_backend() {
  info "Building backend application..."

  (
    cd "${INSTALL_DIR}" || {
      error "Failed to change directory to ${INSTALL_DIR}"
      exit ${EXIT_FAILURE}
    }

    local npm_output
    if ! npm_output=$(npm install 2>&1); then
      error "Failed to install backend dependencies."
      error "${npm_output}"
      exit ${EXIT_FAILURE}
    fi

    if ! npm_output=$(npm run build 2>&1); then
      error "Failed to build backend application."
      error "${npm_output}"
      exit ${EXIT_FAILURE}
    fi
  )

  success "Backend build completed."
}

# Build the frontend: install dependencies and compile UI assets.
# Runs in a subshell to avoid changing the parent shell's working directory.
build_frontend() {
  info "Building frontend application..."

  (
    cd "${INSTALL_DIR}/ui" || {
      error "Failed to change directory to ${INSTALL_DIR}/ui"
      exit ${EXIT_FAILURE}
    }

    local npm_output
    if ! npm_output=$(npm install 2>&1); then
      error "Failed to install frontend dependencies."
      error "${npm_output}"
      exit ${EXIT_FAILURE}
    fi

    if ! npm_output=$(npm run build 2>&1); then
      error "Failed to build frontend application."
      error "${npm_output}"
      exit ${EXIT_FAILURE}
    fi
  )

  success "Frontend build completed."
}

# Verify that expected build artifacts exist after compilation.
verify_build() {
  info "Verifying build artifacts..."

  if [[ ! -f "${INSTALL_DIR}/dist/server/index.js" ]]; then
    error "Build verification failed: ${INSTALL_DIR}/dist/server/index.js not found."
    error "The backend build may have failed silently."
    exit ${EXIT_FAILURE}
  fi

  if [[ ! -f "${INSTALL_DIR}/ui/dist/index.html" ]]; then
    error "Build verification failed: ${INSTALL_DIR}/ui/dist/index.html not found."
    error "The frontend build may have failed silently."
    exit ${EXIT_FAILURE}
  fi

  success "Build artifacts verified: dist/server/index.js and ui/dist/index.html exist."
}

# Orchestrate the full application build: backend, frontend, and verification.
build_application() {
  info "Starting application build..."

  build_backend
  build_frontend
  verify_build

  success "Application build complete."
}

# =============================================================================
# Log Directory Setup
# =============================================================================

# Create /var/log/watcher-mk1 with correct ownership if it does not already exist.
# Idempotent: skips creation if the directory is already present.
setup_log_directory() {
  info "Checking log directory..."

  if [[ -d "${LOG_DIR}" ]]; then
    success "Log directory ${LOG_DIR} already exists. Skipping."
    return 0
  fi

  info "Creating log directory ${LOG_DIR}..."
  sudo mkdir -p "${LOG_DIR}"
  sudo chown "${USER}:${USER}" "${LOG_DIR}"

  success "Log directory ${LOG_DIR} created with ownership ${USER}:${USER}."
}

# =============================================================================
# Service Management
# =============================================================================

# Start Ollama as a background service using systemd.
# Enables the service so it starts automatically on boot.
start_ollama() {
  info "Starting Ollama service via systemd..."

  if ! sudo systemctl enable --now ollama; then
    error "Failed to start Ollama service."
    error "Check systemd logs: journalctl -u ollama"
    exit ${EXIT_FAILURE}
  fi

  success "Ollama service enabled and started."
}

# Start Supermemory server via PM2 on port 6767.
# Uses PM2 idempotency: if the process already exists, restart it instead of
# creating a duplicate entry.
start_supermemory() {
  info "Starting Supermemory via PM2 on port 6767..."

  if pm2 describe supermemory &>/dev/null; then
    info "Supermemory process already exists in PM2. Restarting..."
    if ! pm2 restart supermemory; then
      error "Failed to restart Supermemory via PM2."
      exit ${EXIT_FAILURE}
    fi
  else
    if ! PORT=6767 pm2 start npx --name supermemory -- supermemory@latest local; then
      error "Failed to start Supermemory via PM2."
      error "Check PM2 logs: pm2 logs supermemory"
      exit ${EXIT_FAILURE}
    fi
  fi

  success "Supermemory started via PM2 (port 6767)."
}

# Start the Watcher MK1 application via PM2 using ecosystem.config.cjs.
# Uses PM2 idempotency: if the process already exists, restart it instead of
# creating a duplicate entry.
start_watcher() {
  info "Starting Watcher MK1 via PM2..."

  if pm2 describe watcher-mk1 &>/dev/null; then
    info "Watcher MK1 process already exists in PM2. Restarting..."
    if ! pm2 restart watcher-mk1; then
      error "Failed to restart Watcher MK1 via PM2."
      exit ${EXIT_FAILURE}
    fi
  else
    if ! pm2 start "${INSTALL_DIR}/ecosystem.config.cjs"; then
      error "Failed to start Watcher MK1 via PM2."
      error "Check PM2 logs: pm2 logs watcher-mk1"
      exit ${EXIT_FAILURE}
    fi
  fi

  success "Watcher MK1 started via PM2."
}

# Configure PM2 to start on system boot and save the current process list.
# This ensures all PM2-managed processes restart automatically after a reboot.
configure_pm2_startup() {
  info "Configuring PM2 startup persistence..."

  if ! sudo env PATH="$PATH:$(dirname "$(which node)")" pm2 startup systemd -u "$USER" --hp "$HOME"; then
    error "Failed to configure PM2 startup."
    error "You may need to run the pm2 startup command manually."
    exit ${EXIT_FAILURE}
  fi

  if ! pm2 save; then
    error "Failed to save PM2 process list."
    exit ${EXIT_FAILURE}
  fi

  success "PM2 configured to restart all processes on boot."
}

# Poll the Watcher MK1 health endpoint for up to 30 seconds.
# On success, prints a confirmation message. On timeout, prints diagnostic
# information (PM2 status and recent logs) and exits with an error.
health_check() {
  info "Running health check on http://localhost:4000/api/v1/health..."

  local max_wait=30
  local interval=2
  local elapsed=0

  while [[ ${elapsed} -lt ${max_wait} ]]; do
    if curl -sf --max-time 2 http://localhost:4000/api/v1/health >/dev/null 2>&1; then
      success "Health check passed: Watcher MK1 is responding on port 4000."
      return 0
    fi

    sleep ${interval}
    elapsed=$((elapsed + interval))
    info "Waiting for health check... (${elapsed}s / ${max_wait}s)"
  done

  # Health check timed out — display diagnostics
  error "Health check failed: Watcher MK1 did not respond within ${max_wait} seconds."
  echo ""
  error "── Diagnostic Information ──────────────────────────────────"
  echo ""
  error "PM2 Status:"
  pm2 status || true
  echo ""
  error "Last 20 lines of watcher-mk1 logs:"
  pm2 logs watcher-mk1 --lines 20 --nostream || true
  echo ""
  error "────────────────────────────────────────────────────────────"
  exit ${EXIT_FAILURE}
}

# =============================================================================
# Completion Summary
# =============================================================================

# Display a formatted completion summary with service status, endpoints,
# and next-step guidance after a successful installation.
show_completion_summary() {
  local host_ip
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  # Fallback to hostname if no IP detected
  if [[ -z "${host_ip}" ]]; then
    host_ip="$(hostname)"
  fi

  echo ""
  echo "══════════════════════════════════════════════════════════"
  echo "  Watcher MK1 — Installation Complete"
  echo "══════════════════════════════════════════════════════════"
  echo ""
  echo "  Services:"
  echo "    ✓ Ollama ........... running (systemd)"
  echo "    ✓ Supermemory ...... running (PM2, port 6767)"
  echo "    ✓ Watcher MK1 ..... running (PM2, port 4000)"
  echo ""
  echo "  Endpoints:"
  echo "    API:          http://${host_ip}:4000/api/v1/health"
  echo "    Supermemory:  http://localhost:6767"
  echo ""
  echo "  Next Steps:"
  echo "    1. Register an admin user:"
  echo "       curl -X POST http://${host_ip}:4000/api/v1/auth/register ..."
  echo "    2. Configure AWS credentials in .env (AWS_ACCESS_KEY_ID, etc.)"
  echo "    3. Set up Nginx + SSL (see deploy/README.md, steps 7-8)"
  echo "    4. Connect an AWS account via the UI"
  echo ""
  echo "══════════════════════════════════════════════════════════"
  echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
  echo ""
  info "════════════════════════════════════════════════════════════"
  info "  Watcher MK1 — Production Installer"
  info "════════════════════════════════════════════════════════════"
  echo ""

  # Initialize DB credentials (populated by provision_database if needed)
  DB_USER=""
  DB_PASS=""

  # ── Stage 1: Environment Checks ─────────────────────────────────────────────
  info "────────────────────────────────────────────────────────────"
  info "  Stage 1: Environment Checks"
  info "────────────────────────────────────────────────────────────"
  echo ""

  check_os
  check_sudo

  # ── Stage 2: Dependency Detection & Installation ─────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 2: Dependency Detection & Installation"
  info "────────────────────────────────────────────────────────────"
  echo ""

  install_dependencies

  # ── Stage 3: Database Provisioning ───────────────────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 3: Database Provisioning"
  info "────────────────────────────────────────────────────────────"
  echo ""

  provision_database

  # ── Stage 4: Environment Configuration ───────────────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 4: Environment Configuration"
  info "────────────────────────────────────────────────────────────"
  echo ""

  generate_env

  # ── Stage 5: Application Build ───────────────────────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 5: Application Build"
  info "────────────────────────────────────────────────────────────"
  echo ""

  build_application

  # ── Stage 6: Log Directory Setup ─────────────────────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 6: Log Directory Setup"
  info "────────────────────────────────────────────────────────────"
  echo ""

  setup_log_directory

  # ── Stage 7: Service Startup ─────────────────────────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 7: Service Startup"
  info "────────────────────────────────────────────────────────────"
  echo ""

  start_ollama
  start_supermemory
  start_watcher
  configure_pm2_startup

  # ── Stage 8: Health Check ────────────────────────────────────────────────────
  echo ""
  info "────────────────────────────────────────────────────────────"
  info "  Stage 8: Health Check"
  info "────────────────────────────────────────────────────────────"
  echo ""

  health_check

  # ── Stage 9: Complete ────────────────────────────────────────────────────────
  echo ""

  show_completion_summary
}

main "$@"
