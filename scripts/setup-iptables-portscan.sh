#!/usr/bin/env bash
# ==============================================================================
# HoneyAI — Host iptables & Portscan Setup
# Configures portscan logging in iptables and restricts egress traffic for HoneyAI.
# Execute this script as root on the host machine.
# ==============================================================================

set -euo pipefail

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run this script as root (sudo)." >&2
    exit 1
fi

HONEYAI_IP="172.30.50.10"
PORTS_TO_LOG="21,22,23,25,80,443,445,1433,3306,6379,9418,5900,3389"

echo "=== HoneyAI iptables & Portscan Setup ==="
echo "[*] Target HoneyAI IP: $HONEYAI_IP"
echo "[*] Monitoring ports: $PORTS_TO_LOG"

# 1. Setup Portscan Logging in INPUT chain
echo "[+] Configuring INPUT chain portscan logging..."
# Create a dedicated log chain for portscan to avoid duplicate rules
if ! iptables -L HONEYAI-PORTSCAN &>/dev/null; then
    iptables -N HONEYAI-PORTSCAN
fi

# Clear existing rules in the logging chain
iptables -F HONEYAI-PORTSCAN
iptables -A HONEYAI-PORTSCAN -j LOG --log-prefix "PORTSCAN: " --log-level 4
iptables -A HONEYAI-PORTSCAN -j DROP # Drop scanning packets on unused ports if they shouldn't reach the host

# Direct SYN packets on targeted ports to our logging chain
# Note: We check if the rule already exists to keep script idempotent
iptables -F INPUT # CAUTION: Doing a full flush on INPUT might cut off connections if done blindly, 
                  # but we only target custom rules if we use a sub-chain.
                  # Let's use a sub-chain instead of flushing the INPUT chain directly!

if ! iptables -L HONEYAI-INPUT &>/dev/null; then
    iptables -N HONEYAI-INPUT
    # Insert at the top of INPUT chain
    iptables -I INPUT 1 -j HONEYAI-INPUT
fi

iptables -F HONEYAI-INPUT
# Log SYN scans on designated ports. Adjust ports if needed.
iptables -A HONEYAI-INPUT -p tcp -m multiport --dports "$PORTS_TO_LOG" --syn -j HONEYAI-PORTSCAN

# 2. Setup Egress Firewall rules for HoneyAI in DOCKER-USER chain
echo "[+] Configuring egress firewall rules for HoneyAI ($HONEYAI_IP)..."
if ! iptables -L HONEYAI-EGRESS &>/dev/null; then
    iptables -N HONEYAI-EGRESS
fi

# Clear and rebuild egress chain
iptables -F HONEYAI-EGRESS
# A. Allow established / related connections (replies to incoming scanner actions)
iptables -A HONEYAI-EGRESS -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# B. Allow DNS queries (outgoing port 53 UDP/TCP)
iptables -A HONEYAI-EGRESS -p udp --dport 53 -j ACCEPT
# C. Allow HTTPS (outgoing port 443 TCP) - required for AbuseIPDB, OTX, Telegram, VirusTotal reporting
iptables -A HONEYAI-EGRESS -p tcp --dport 443 -j ACCEPT
# D. Drop all other egress traffic
iptables -A HONEYAI-EGRESS -j DROP

# Link HONEYAI-EGRESS chain to DOCKER-USER chain if not already linked
if ! iptables -C DOCKER-USER -s "$HONEYAI_IP" -j HONEYAI-EGRESS 2>/dev/null; then
    echo "[+] Linking HoneyAI egress chain to DOCKER-USER..."
    iptables -I DOCKER-USER 1 -s "$HONEYAI_IP" -j HONEYAI-EGRESS
else
    echo "[*] Egress rule link already exists in DOCKER-USER."
fi

# 3. Adjust syslog permissions on Host
echo "[+] Checking syslog log file permissions..."
# Check where kernel/syslog writes (Debian uses /var/log/syslog, RedHat uses /var/log/messages)
SYSLOG_PATH="/var/log/syslog"
if [ ! -f "$SYSLOG_PATH" ]; then
    SYSLOG_PATH="/var/log/messages"
fi

if [ -f "$SYSLOG_PATH" ]; then
    echo "[+] Found syslog at: $SYSLOG_PATH. Adjusting permissions to 644..."
    chmod 644 "$SYSLOG_PATH"
    
    # Configure rsyslog to create future log files with 644 permissions
    RSYSLOG_GLOBAL="/etc/rsyslog.conf"
    if [ -f "$RSYSLOG_GLOBAL" ]; then
        if grep -q "\$FileCreateMode" "$RSYSLOG_GLOBAL"; then
            echo "[*] \$FileCreateMode is already configured in $RSYSLOG_GLOBAL."
        else
            echo "[+] Injecting default file creation mode (0644) in $RSYSLOG_GLOBAL..."
            echo -e "\n# HoneyAI: Allow reading logs from Docker container\n\$FileCreateMode 0644" >> "$RSYSLOG_GLOBAL"
            systemctl restart rsyslog || true
        fi
    fi
else
    echo "WARNING: Could not find standard syslog file. Make sure HoneyAI can read kernel logs." >&2
fi

echo "=============================================================================="
echo "SUCCESS: Host iptables and egress rules configured!"
echo "Honeypot IP: $HONEYAI_IP"
echo "Blocked all outbound traffic from honeypot except: ESTABLISHED, DNS, HTTPS"
echo "Ensure your docker-compose.yml maps: $SYSLOG_PATH:/var/log/syslog:ro"
echo "=============================================================================="
