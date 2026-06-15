#!/usr/bin/env bash
# ==============================================================================
# HoneyAI — Host Samba VFS Audit Log Setup
# Configures Samba VFS auditing on the host and exposes the log to the honeypot.
# Execute this script as root on the host machine.
# ==============================================================================

set -euo pipefail

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run this script as root (sudo)." >&2
    exit 1
fi

echo "=== HoneyAI Samba VFS Audit Log Setup ==="

# 1. Install dependencies if missing
INSTALL_PACKAGES=()
if ! command -v smbd &>/dev/null; then
    INSTALL_PACKAGES+=("samba")
fi
if ! command -v rsyslogd &>/dev/null; then
    INSTALL_PACKAGES+=("rsyslog")
fi

if [ ${#INSTALL_PACKAGES[@]} -gt 0 ]; then
    echo "[+] Installing missing packages: ${INSTALL_PACKAGES[*]}..."
    apt-get update -qy
    apt-get install -qy "${INSTALL_PACKAGES[@]}"
else
    echo "[*] All required packages (Samba, rsyslog) are already installed."
fi

# 2. Setup directory for fake files
SHARE_DIR="/srv/samba/share_docs"
if [ ! -d "$SHARE_DIR" ]; then
    echo "[+] Creating share directory: $SHARE_DIR"
    mkdir -p "$SHARE_DIR"
    chown -R nobody:nogroup "$SHARE_DIR"
    chmod -R 777 "$SHARE_DIR"
    
    # Create some juicy bait files
    echo "admin:password123" > "$SHARE_DIR/credentials.txt"
    echo "This is a private corporate directory." > "$SHARE_DIR/readme.md"
    echo "192.168.1.1 master_db" > "$SHARE_DIR/hosts_map.bak"
fi

# 3. Configure smb.conf
SMB_CONF="/etc/samba/smb.conf"
SHARE_NAME="CorporateFiles"

if grep -q "\[$SHARE_NAME\]" "$SMB_CONF"; then
    echo "[*] Share [$SHARE_NAME] already exists in $SMB_CONF."
else
    echo "[+] Adding share and VFS audit settings to $SMB_CONF..."
    cat <<EOF >> "$SMB_CONF"

# --- HoneyAI Bait Share with VFS Audit ---
[$SHARE_NAME]
    path = $SHARE_DIR
    browseable = yes
    read only = no
    guest ok = yes
    force user = nobody
    vfs objects = full_audit
    full_audit:prefix = %u|%I|%m|%S
    full_audit:success = connect disconnect open opendir read pread write pwrite unlink rmdir rename mkdir
    full_audit:failure = connect open opendir read pread write pwrite unlink rmdir rename mkdir
    full_audit:facility = local7
    full_audit:priority = NOTICE
EOF
fi

# 4. Configure rsyslog
RSYSLOG_CONF="/etc/rsyslog.d/samba-audit.conf"
AUDIT_LOG="/var/log/samba/full_audit.log"

echo "[+] Configuring rsyslog to write local7 to $AUDIT_LOG..."
cat <<EOF > "$RSYSLOG_CONF"
# Log Samba VFS audit events to a dedicated log file
local7.notice $AUDIT_LOG
& stop
EOF

# 5. Create audit log and set permissions
echo "[+] Creating log file and fixing permissions..."
touch "$AUDIT_LOG"
# Allow others to read so HoneyAI docker container user can parse it
chmod 644 "$AUDIT_LOG"
chmod 755 /var/log/samba

# Configure logrotate for the audit log
LOGROTATE_CONF="/etc/logrotate.d/samba-audit"
if [ ! -f "$LOGROTATE_CONF" ]; then
    echo "[+] Creating logrotate configuration..."
    cat <<EOF > "$LOGROTATE_CONF"
$AUDIT_LOG {
    weekly
    missingok
    rotate 4
    compress
    delaycompress
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate || systemctl kill -s HUP rsyslog.service
    endscript
}
EOF
fi

# 6. Restart services
echo "[+] Restarting Samba and rsyslog..."
systemctl restart rsyslog
systemctl restart smbd
if systemctl is-active --quiet nmbd; then
    systemctl restart nmbd
fi

echo "=============================================================================="
echo "SUCCESS: Host Samba VFS auditing configured!"
echo "Audit Log: $AUDIT_LOG"
echo "Bait share directory: $SHARE_DIR"
echo "Ensure your docker-compose.yml maps: $AUDIT_LOG:/var/log/samba/full_audit.log:ro"
echo "=============================================================================="
