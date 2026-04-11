#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}[-]${NC} Run as root: sudo $0"; exit 1; }

echo "Uninstalling ProxiFlare..."

# Stop service
systemctl stop proxiflare-daemon 2>/dev/null || true
systemctl disable proxiflare-daemon 2>/dev/null || true

# Remove binaries
rm -f /usr/local/bin/proxiflare-daemon
rm -f /usr/local/bin/proxiflare
info "Binaries removed"

# Remove systemd + polkit
rm -f /etc/systemd/system/proxiflare-daemon.service
rm -f /usr/share/polkit-1/actions/com.proxiflare.policy
systemctl daemon-reload
info "Service removed"

# Remove desktop entry + icons
rm -f /usr/share/applications/proxiflare.desktop
find /usr/share/icons -name "proxiflare*" -delete 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
info "Desktop entry removed"

# Ask about data
read -p "Remove config and database? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/proxiflare
    rm -rf /var/lib/proxiflare
    rm -rf /var/log/proxiflare
    info "Data removed"
else
    echo "Data kept at /etc/proxiflare, /var/lib/proxiflare, /var/log/proxiflare"
fi

info "ProxiFlare uninstalled."
