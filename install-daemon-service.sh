#!/bin/bash
# QKS Daemon Service Setup Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/qks-daemon.service"
DAEMON_NAME="qks_daemon"
INSTALL_DIR="/opt/qks"
LOG_DIR="/var/log/qks"
BIN_PATH="/usr/local/bin/qks_daemon"

echo "=== QKS Daemon Service Setup ==="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

# Create installation directories
echo "[1/5] Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Copy daemon binary (user must build it first)
echo "[2/5] Setting up daemon binary..."
if [ ! -f "$SCRIPT_DIR/daemon/$DAEMON_NAME" ]; then
    echo "ERROR: Daemon binary not found at $SCRIPT_DIR/daemon/$DAEMON_NAME"
    echo "Please build the daemon first:"
    echo "  cd $SCRIPT_DIR/daemon && make"
    exit 1
fi

cp "$SCRIPT_DIR/daemon/$DAEMON_NAME" "$BIN_PATH"
chmod 755 "$BIN_PATH"
echo "  Installed: $BIN_PATH"

# Copy daemon files to /opt/qks
echo "[3/5] Copying daemon files..."

# Copy policy directory
if [ -d "$SCRIPT_DIR/daemon/policy" ]; then
    cp -r "$SCRIPT_DIR/daemon/policy" "$INSTALL_DIR/"
    echo "  ✓ Policy files copied"
else
    echo "  Note: policy directory not found"
fi

# Copy ML-DSA key files (critical)
if [ -f "$SCRIPT_DIR/daemon/qks_sk.bin" ]; then
    cp "$SCRIPT_DIR/daemon/qks_sk.bin" "$INSTALL_DIR/"
    chmod 600 "$INSTALL_DIR/qks_sk.bin"
    echo "  ✓ Private key (qks_sk.bin) copied"
else
    echo "  WARNING: qks_sk.bin not found - daemon will fail!"
fi

if [ -f "$SCRIPT_DIR/daemon/qks_pk.bin" ]; then
    cp "$SCRIPT_DIR/daemon/qks_pk.bin" "$INSTALL_DIR/"
    chmod 644 "$INSTALL_DIR/qks_pk.bin"
    echo "  ✓ Public key (qks_pk.bin) copied"
else
    echo "  WARNING: qks_pk.bin not found - daemon will fail!"
fi

chmod -R 755 "$INSTALL_DIR"
echo "  Daemon files copied to: $INSTALL_DIR"

# Install systemd service
echo "[4/5] Installing systemd service..."
cp "$SERVICE_FILE" /etc/systemd/system/
systemctl daemon-reload
echo "  Service installed: /etc/systemd/system/qks-daemon.service"

# Create log rotation config
echo "[5/5] Setting up log rotation..."
cat > /etc/logrotate.d/qks-daemon << 'EOF'
/var/log/qks/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
}
EOF
echo "  Log rotation configured"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Start the daemon:"
echo "     sudo systemctl start qks-daemon"
echo ""
echo "  2. Check status:"
echo "     sudo systemctl status qks-daemon"
echo ""
echo "  3. View logs (live):"
echo "     sudo journalctl -u qks-daemon -f"
echo ""
echo "  4. Enable auto-start on boot:"
echo "     sudo systemctl enable qks-daemon"
echo ""
echo "  5. View logs in /var/log/qks/:"
echo "     sudo tail -f /var/log/qks/qks-daemon.log"
echo ""
