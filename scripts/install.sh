#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/proxiflare"
DATA_DIR="/var/lib/proxiflare"
LOG_DIR="/var/log/proxiflare"

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

echo -e "${CYAN}"
echo "  ____                 _ _____ _"
echo " |  _ \ _ __ _____  _(_)  ___| | __ _ _ __ ___"
echo " | |_) | '__/ _ \ \/ / | |_  | |/ _\` | '__/ _ \\"
echo " |  __/| | | (_) >  <| |  _| | | (_| | | |  __/"
echo " |_|   |_|  \___/_/\_\_|_|   |_|\__,_|_|  \___|"
echo -e "${NC}"
echo "  Professional Proxy Router for Linux v1.0.0"
echo ""

# Check root
[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"
[[ "$(uname)" != "Linux" ]] && error "Linux only"

info "Installing ProxiFlare v1.0.0..."

# Check/install build dependencies
info "Checking dependencies..."
DEPS="build-essential cmake pkg-config libsqlite3-dev libnetfilter-queue-dev libnfnetlink-dev libssh2-1-dev libssl-dev libargon2-dev nftables"
apt-get update -qq 2>/dev/null
for dep in $DEPS; do
    dpkg -s "$dep" >/dev/null 2>&1 || apt-get install -y -qq "$dep" >/dev/null 2>&1
done

# Check Node.js
command -v node >/dev/null || error "Node.js >= 18 required. Install: https://nodejs.org"
# Check Rust
command -v cargo >/dev/null || {
    if [ -f "$HOME/.cargo/env" ]; then source "$HOME/.cargo/env"; fi
    command -v cargo >/dev/null || error "Rust required. Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
}

# Build daemon
info "Building daemon..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR/daemon"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-O2" >/dev/null 2>&1
make -j$(nproc) >/dev/null 2>&1
info "Daemon built successfully"

# Build GUI
info "Building GUI (this may take a few minutes)..."
cd "$PROJECT_DIR/gui"
npm install --silent 2>/dev/null
npx tauri build 2>/dev/null || warn "GUI build failed — install daemon only"
cd "$PROJECT_DIR"

# Install binaries
info "Installing binaries..."
install -m 755 daemon/build/proxiflare-daemon "$INSTALL_DIR/"
if [ -f "gui/src-tauri/target/release/proxiflare" ]; then
    install -m 755 gui/src-tauri/target/release/proxiflare "$INSTALL_DIR/"
elif [ -f "gui/src-tauri/target/release/proxi-flare" ]; then
    install -m 755 gui/src-tauri/target/release/proxi-flare "$INSTALL_DIR/proxiflare"
else
    warn "GUI binary not found — daemon-only install"
fi

# Create directories
install -d -m 755 "$CONFIG_DIR"
install -d -m 700 "$DATA_DIR"
install -d -m 755 "$LOG_DIR"

# Install systemd service (disabled by default)
install -m 644 scripts/proxiflare-daemon.service /etc/systemd/system/
systemctl daemon-reload

# Install polkit policy
install -m 644 scripts/com.proxiflare.policy /usr/share/polkit-1/actions/ 2>/dev/null || true

# Install desktop entry
cat > /usr/share/applications/proxiflare.desktop << 'DESKTOP'
[Desktop Entry]
Name=ProxiFlare
Comment=Professional Proxy Router for Linux
Exec=proxiflare
Icon=proxiflare
Type=Application
Categories=Network;Security;
StartupWMClass=proxiflare
DESKTOP

# Install icons
for size in 16 32 128 256 512; do
    dir="/usr/share/icons/hicolor/${size}x${size}/apps"
    install -d "$dir"
    [ -f "$PROJECT_DIR/assets/icon-${size}.png" ] && install -m 644 "$PROJECT_DIR/assets/icon-${size}.png" "$dir/proxiflare.png"
done
install -d /usr/share/icons/hicolor/scalable/apps
[ -f "$PROJECT_DIR/assets/logo.svg" ] && install -m 644 "$PROJECT_DIR/assets/logo.svg" /usr/share/icons/hicolor/scalable/apps/proxiflare.svg
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

echo ""
info "Installation complete!"
echo ""
echo -e "  ${CYAN}Start daemon:${NC}   sudo systemctl start proxiflare-daemon"
echo -e "  ${CYAN}Enable boot:${NC}    sudo systemctl enable proxiflare-daemon"
echo -e "  ${CYAN}Launch GUI:${NC}     proxiflare"
echo ""
echo -e "  Or toggle 'Start at Boot' from the GUI Settings tab."
echo ""
