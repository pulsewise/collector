#!/bin/bash

set -e

# ─────────────────────────────────────────────────────────────
# Pulsewise Collector — One-click installer
# Usage: curl -sSL https://pulsewise.app/install-collector.sh | TOKEN=your-token sudo -E bash
# ─────────────────────────────────────────────────────────────

# Colors
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)  OS_SLUG="linux" ;;
    darwin) OS_SLUG="darwin" ;;
    *)
        echo -e "\033[0;31mUnsupported OS: $OS\033[0m"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)  ARCH_SLUG="amd64" ;;
    aarch64|arm64) ARCH_SLUG="arm64" ;;
    *)
        echo -e "\033[0;31mUnsupported architecture: $ARCH\033[0m"
        exit 1
        ;;
esac

# Configuration
BINARY_URL="https://pulsewise.app/collector/download/${OS_SLUG}-${ARCH_SLUG}"
BINARY_PATH="/usr/local/bin/pulsewise-collector"
CONFIG_DIR="/etc/pulsewise-collector"
CONFIG_FILE="${CONFIG_DIR}/config"
SERVICE_NAME="pulsewise-collector"
LAUNCHD_LABEL="app.pulsewise.collector"
LAUNCHD_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
SYSTEMD_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

print_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ┌─────────────────────────────────────┐"
    echo "  │       Pulsewise Collector Setup      │"
    echo "  │                                      │"
    echo "  │   System monitoring made simple.     │"
    echo "  └─────────────────────────────────────┘"
    echo -e "${NC}"
    echo ""
}

step() {
    echo -e "  ${CYAN}${BOLD}[$1/4]${NC} ${BOLD}$2${NC}"
}

info() {
    echo -e "       $1"
}

success() {
    echo -e "       ${GREEN}$1${NC}"
}

warn() {
    echo -e "       ${YELLOW}$1${NC}"
}

fail() {
    echo -e "\n  ${RED}${BOLD}Error:${NC} $1\n"
    exit 1
}

prompt() {
    local var_name="$1"
    local prompt_text="$2"
    local default_val="$3"
    local secret="$4"
    local value=""

    if [ -n "$default_val" ]; then
        prompt_text="${prompt_text} ${DIM}[${default_val}]${NC}"
    fi

    echo ""
    if [ "$secret" = "true" ]; then
        echo -ne "       ${BOLD}${prompt_text}:${NC} "
        read -rs value
        echo ""
    else
        echo -ne "       ${BOLD}${prompt_text}:${NC} "
        read -r value
    fi

    if [ -z "$value" ] && [ -n "$default_val" ]; then
        value="$default_val"
    fi

    eval "$var_name=\"$value\""
}

stop_existing_service() {
    if [ "$OS_SLUG" = "linux" ]; then
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            info "Stopping existing service..."
            systemctl stop "$SERVICE_NAME"
        fi
    elif [ "$OS_SLUG" = "darwin" ]; then
        if launchctl list "$LAUNCHD_LABEL" &>/dev/null; then
            info "Stopping existing service..."
            launchctl bootout system "$LAUNCHD_PLIST" 2>/dev/null || true
        fi
    fi
}

register_service() {
    if [ "$OS_SLUG" = "linux" ]; then
        if ! command -v systemctl &> /dev/null; then
            fail "systemd is required but not found on this system."
        fi

        cat > "$SYSTEMD_FILE" <<EOF
[Unit]
Description=Pulsewise Collector
After=network.target

[Service]
Type=simple
User=root
ExecStart=$BINARY_PATH
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        success "systemd service registered"

    elif [ "$OS_SLUG" = "darwin" ]; then
        cat > "$LAUNCHD_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${BINARY_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/pulsewise-collector.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/pulsewise-collector.log</string>
</dict>
</plist>
EOF
        success "launchd service registered"
    fi
}

start_service() {
    if [ "$OS_SLUG" = "linux" ]; then
        systemctl enable --quiet "$SERVICE_NAME"
        systemctl start "$SERVICE_NAME"

        sleep 1
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            success "Service is running"
        else
            warn "Service may not have started. Check: journalctl -u $SERVICE_NAME -n 20"
        fi

    elif [ "$OS_SLUG" = "darwin" ]; then
        launchctl bootstrap system "$LAUNCHD_PLIST"

        sleep 1
        if launchctl list "$LAUNCHD_LABEL" &>/dev/null; then
            success "Service is running"
        else
            warn "Service may not have started. Check: /var/log/pulsewise-collector.log"
        fi
    fi
}

print_summary() {
    echo ""
    echo -e "  ${GREEN}${BOLD}Setup complete.${NC}"
    echo ""
    echo -e "  ${DIM}Hostname:${NC} $COLLECTOR_HOSTNAME"
    echo -e "  ${DIM}Config:${NC}   $CONFIG_FILE"
    echo -e "  ${DIM}Binary:${NC}   $BINARY_PATH"
    echo ""

    if [ "$OS_SLUG" = "linux" ]; then
        echo -e "  ${DIM}Useful commands:${NC}"
        echo -e "    journalctl -u $SERVICE_NAME -f      ${DIM}# follow logs${NC}"
        echo -e "    systemctl status $SERVICE_NAME       ${DIM}# check status${NC}"
        echo -e "    systemctl restart $SERVICE_NAME      ${DIM}# restart${NC}"
    elif [ "$OS_SLUG" = "darwin" ]; then
        echo -e "  ${DIM}Useful commands:${NC}"
        echo -e "    tail -f /var/log/pulsewise-collector.log   ${DIM}# follow logs${NC}"
        echo -e "    sudo launchctl kickstart -k system/${LAUNCHD_LABEL}  ${DIM}# restart${NC}"
        echo -e "    sudo launchctl bootout system ${LAUNCHD_PLIST}       ${DIM}# stop${NC}"
    fi

    echo ""
}

# ─────────────────────────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────────────────────────

print_banner

# Must be root
if [ "$EUID" -ne 0 ]; then
    fail "Please run as root:\n\n       ${DIM}curl -sSL https://pulsewise.app/install-collector.sh | TOKEN=your-token sudo -E bash${NC}"
fi

# Check for existing installation
if [ -f "$BINARY_PATH" ] || [ -f "$CONFIG_FILE" ]; then
    warn "An existing Pulsewise installation was detected."
    echo ""
    echo -ne "       ${BOLD}Reinstall and overwrite? (y/N):${NC} "
    read -r -n 1 REPLY
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "\n  Installation cancelled.\n"
        exit 0
    fi
    echo ""
    stop_existing_service
fi

# ─────────────────────────────────────────────────────────────
# Onboarding
# ─────────────────────────────────────────────────────────────

echo -e "  ${DIM}Let's get your collector set up. This takes about 30 seconds.${NC}"

# Token — use env var if provided, otherwise prompt
if [ -z "$TOKEN" ]; then
    prompt TOKEN "Pulsewise token" "" "true"
    if [ -z "$TOKEN" ]; then
        fail "A token is required. Find yours at https://pulsewise.app/settings/tokens"
    fi
else
    success "Token provided via environment"
fi

# Hostname — use env var if provided, otherwise prompt with system default
if [ -z "$COLLECTOR_HOSTNAME" ]; then
    DEFAULT_HOSTNAME=$(hostname -s 2>/dev/null || hostname)
    prompt COLLECTOR_HOSTNAME "Hostname" "$DEFAULT_HOSTNAME"
    if [ -z "$COLLECTOR_HOSTNAME" ]; then
        COLLECTOR_HOSTNAME="$DEFAULT_HOSTNAME"
    fi
else
    success "Hostname: $COLLECTOR_HOSTNAME"
fi

# ─────────────────────────────────────────────────────────────
# Installation
# ─────────────────────────────────────────────────────────────

echo ""

# Step 1: Download binary
step 1 "Downloading collector..."
TEMP_BINARY=$(mktemp)
if command -v curl &> /dev/null; then
    HTTP_CODE=$(curl -fsSL -o "$TEMP_BINARY" -w "%{http_code}" "$BINARY_URL" 2>/dev/null) || true
elif command -v wget &> /dev/null; then
    wget -q -O "$TEMP_BINARY" "$BINARY_URL" 2>/dev/null && HTTP_CODE="200" || HTTP_CODE="000"
else
    fail "Neither curl nor wget is available. Install one and try again."
fi

if [ ! -s "$TEMP_BINARY" ] || [ "$HTTP_CODE" != "200" ]; then
    rm -f "$TEMP_BINARY"
    fail "Download failed (HTTP $HTTP_CODE). Check your network and try again."
fi

chmod +x "$TEMP_BINARY"
mkdir -p "$(dirname "$BINARY_PATH")"
mv "$TEMP_BINARY" "$BINARY_PATH"
success "Installed to $BINARY_PATH"

# Step 2: Write configuration
step 2 "Writing configuration..."
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_FILE" <<EOF
# Pulsewise Collector Configuration
# Docs: https://pulsewise.app/docs/collector

TOKEN=$TOKEN
HOSTNAME=$COLLECTOR_HOSTNAME
EOF
chmod 600 "$CONFIG_FILE"
success "Config saved to $CONFIG_FILE"

# Step 3: Register service
step 3 "Registering service..."
register_service

# Step 4: Start
step 4 "Starting collector..."
start_service

# Done
print_summary
