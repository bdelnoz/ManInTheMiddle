#!/bin/bash
################################################################################
# Author: Bruno DELNOZ
# Email: bruno.delnoz@protonmail.com
# Script name with full path: /mnt/data2_78g/Security/scripts/Projects_security/ManInTheMiddle/mitm-sourcesvr.sh
# Target usage: MITM router setup for SOURCESVR traffic capture and analysis
# Version: v3.2 – Date: 2025-02-03
#
# Changelog:
# v3.2 - 2025-02-03 - DUAL MODE: Router (default) + Capture
# Added --router mode (default, permanent, minimal logs, no backup)
# Added --capture mode (verbose logs, system backup, analysis)
# Configuration file stored in script directory: ./mitm-router.conf
# Added systemd service installation (--install-service)
# Added --uninstall-service to remove systemd service
# Mode auto-detection: default is --router if not specified
# Logs optimized per mode (minimal for router, verbose for capture)
# Added persistent configuration loading from ./mitm-router.conf
# v3.1 - 2025-02-03 - BUG FIXES & IMPROVEMENTS
# Fixed critical duplicate --stop argument parsing
# Fixed --start/-st and --stop/-st alias conflict (now -sta and -sto)
# Added post-startup healthcheck verification (verify_mitm_status)
# Added show_traffic_stats() function for monitoring
# Added export_config_json() for configuration export
# Added auto-detection of network interfaces
# Improved error handling for hostapd/dnsmasq failures
# Added input validation for WiFi password length
# Cleaned up obsolete TODOs
################################################################################
set -e

################################################################################
# DEFAULT CONFIGURATION VARIABLES
################################################################################
# Operating mode (router or capture)
MODE="router"  # Default mode

# Network Interfaces
LAN_IF="eth1"                        # Ethernet interface for SOURCESVR device
WAN_IF="wlan0"                       # Interface connected to Internet
WIFI_IF="wlan1"                      # WiFi interface for hotspot MITM

# LAN Configuration
LAN_IP="192.168.50.1"                # IP address for LAN gateway (Ethernet)
LAN_NETMASK="24"                     # Netmask for LAN network
DHCP_RANGE_START="192.168.50.10"     # DHCP pool start address (Ethernet)
DHCP_RANGE_END="192.168.50.50"       # DHCP pool end address (Ethernet)
DHCP_LEASE_TIME="12h"                # DHCP lease duration
DNS1_IP="1.1.1.1"
DNS2_IP="1.0.0.1"

# WiFi Hotspot Configuration
WIFI_ENABLED="true"                  # WiFi hotspot ENABLED by default
WIFI_IP="192.168.51.1"               # IP address for WiFi gateway
WIFI_NETMASK="24"                    # Netmask for WiFi network
WIFI_DHCP_START="192.168.51.10"      # DHCP pool start for WiFi
WIFI_DHCP_END="192.168.51.50"        # DHCP pool end for WiFi
WIFI_SSID="WLAN_MITM"                # SSID of the WiFi hotspot
WIFI_PASSWORD="Mitm123456.2026"      # WPA2 password (min 8 chars)
WIFI_BAND="a"                        # WiFi band: a=5GHz, g=2.4GHz
WIFI_CHANNEL="36"                    # WiFi channel (5GHz: 36,40,44,48 / 2.4GHz: 1-13)
WIFI_COUNTRY="BE"                    # Country code (Belgium)

################################################################################
# PATHS AND FILES
################################################################################
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VERSION="v3.2"

# Configuration file (persistent, stored in script directory)
CONFIG_FILE="${SCRIPT_DIR}/mitm-router.conf"

# Create required directories
LOGS_DIR="${SCRIPT_DIR}/logs"
RESULTS_DIR="${SCRIPT_DIR}/results"
INFOS_DIR="${SCRIPT_DIR}/infos"
RUNS_DIR="${SCRIPT_DIR}/runs"
mkdir -p "$LOGS_DIR" "$RESULTS_DIR" "$INFOS_DIR" "$RUNS_DIR"

# Log file (mode-dependent)
LOGFILE="${LOGS_DIR}/log.${SCRIPT_NAME}.${TIMESTAMP}.${VERSION}.log"

# State backup file (only in capture mode)
STATE_BACKUP="${RESULTS_DIR}/system-state-backup.${TIMESTAMP}.tar.gz"

# Runtime files - ALWAYS in ./runs/ directory (never in /tmp)
if [ "$MODE" = "router" ]; then
    DNSMASQ_CONF="${RUNS_DIR}/dnsmasq-router.conf"
    DNSMASQ_PID="${RUNS_DIR}/dnsmasq-router.pid"
    HOSTAPD_CONF="${RUNS_DIR}/hostapd-router.conf"
    HOSTAPD_PID="${RUNS_DIR}/hostapd-router.pid"
    STATE_FILE="${RUNS_DIR}/mitm-router-state.txt"
else
    DNSMASQ_CONF="${RUNS_DIR}/dnsmasq-capture-${TIMESTAMP}.conf"
    DNSMASQ_PID="${RUNS_DIR}/dnsmasq-capture-${TIMESTAMP}.pid"
    HOSTAPD_CONF="${RUNS_DIR}/hostapd-capture-${TIMESTAMP}.conf"
    HOSTAPD_PID="${RUNS_DIR}/hostapd-capture-${TIMESTAMP}.pid"
    STATE_FILE="${RUNS_DIR}/mitm-capture-state-${TIMESTAMP}.txt"
fi

################################################################################
# LOGGING FUNCTION (MODE-AWARE)
################################################################################
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"

    if [ "$MODE" = "capture" ]; then
        # Verbose logging for capture mode
        echo "$message" | tee -a "$LOGFILE"
    else
        # Minimal logging for router mode (only errors and important info)
        if [[ "$1" == *"Error"* ]] || [[ "$1" == *"ERROR"* ]] || [[ "$1" == *"✗"* ]]; then
            echo "$message" | tee -a "$LOGFILE"
        else
            echo "$message" >> "$LOGFILE"
        fi
    fi
}

################################################################################
# LOAD CONFIGURATION FROM FILE
################################################################################
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        log "[Config] Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
        log "[Config] Configuration loaded successfully"
    else
        log "[Config] No configuration file found, using defaults"
    fi
}

################################################################################
# SAVE CONFIGURATION TO FILE
################################################################################
save_config() {
    log "[Config] Saving configuration to $CONFIG_FILE"
    cat > "$CONFIG_FILE" <<EOF
# MITM Router Configuration
# Generated: $(date)
# Version: ${VERSION}

# Network Interfaces
LAN_IF="$LAN_IF"
WAN_IF="$WAN_IF"
WIFI_IF="$WIFI_IF"

# LAN Configuration
LAN_IP="$LAN_IP"
LAN_NETMASK="$LAN_NETMASK"
DHCP_RANGE_START="$DHCP_RANGE_START"
DHCP_RANGE_END="$DHCP_RANGE_END"
DHCP_LEASE_TIME="$DHCP_LEASE_TIME"
DNS1_IP="$DNS1_IP"
DNS2_IP="$DNS2_IP"

# WiFi Hotspot Configuration
WIFI_ENABLED="$WIFI_ENABLED"
WIFI_IP="$WIFI_IP"
WIFI_NETMASK="$WIFI_NETMASK"
WIFI_DHCP_START="$WIFI_DHCP_START"
WIFI_DHCP_END="$WIFI_DHCP_END"
WIFI_SSID="$WIFI_SSID"
WIFI_PASSWORD="$WIFI_PASSWORD"
WIFI_BAND="$WIFI_BAND"
WIFI_CHANNEL="$WIFI_CHANNEL"
WIFI_COUNTRY="$WIFI_COUNTRY"
EOF
    log "[Config] Configuration saved"
}

################################################################################
# SYSTEMD SERVICE INSTALLATION
################################################################################
install_systemd_service() {
    log "[Service] Installing systemd service"

    local service_file="/etc/systemd/system/mitm-router.service"

    cat > "$service_file" <<EOF
[Unit]
Description=MITM Router Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${SCRIPT_DIR}/${SCRIPT_NAME} --router --exec
ExecStop=${SCRIPT_DIR}/${SCRIPT_NAME} --stop
TimeoutStartSec=0
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "[Service] Systemd service installed at $service_file"
    log "[Service] Enable with: sudo systemctl enable mitm-router"
    log "[Service] Start with: sudo systemctl start mitm-router"
    log "[Service] Status with: sudo systemctl status mitm-router"
}

################################################################################
# SYSTEMD SERVICE UNINSTALLATION
################################################################################
uninstall_systemd_service() {
    log "[Service] Uninstalling systemd service"

    systemctl stop mitm-router 2>/dev/null || true
    systemctl disable mitm-router 2>/dev/null || true
    rm -f /etc/systemd/system/mitm-router.service
    systemctl daemon-reload

    log "[Service] Systemd service uninstalled"
}

################################################################################
# GITIGNORE MANAGEMENT
################################################################################
manage_gitignore() {
    log "[GitIgnore] Managing .gitignore file"
    local gitignore_file="${SCRIPT_DIR}/.gitignore"
    local entries_to_add=("/logs" "/results" "/outputs" "/infos" "/runs")
    local added_count=0

    # Create .gitignore if it doesn't exist
    if [ ! -f "$gitignore_file" ]; then
        log "[GitIgnore] Creating new .gitignore file"
        touch "$gitignore_file"
    fi

    # Add section header comment
    if ! grep -q "Section added automatically by ${SCRIPT_NAME}" "$gitignore_file" 2>/dev/null; then
        echo "" >> "$gitignore_file"
        echo "# Section added automatically by ${SCRIPT_NAME}" >> "$gitignore_file"
    fi

    # Check and add each entry
    for entry in "${entries_to_add[@]}"; do
        if ! grep -qxF "$entry" "$gitignore_file" 2>/dev/null; then
            echo "$entry" >> "$gitignore_file"
            log "[GitIgnore] Added entry: $entry"
            ((added_count++))
        fi
    done

    if [ $added_count -eq 0 ]; then
        log "[GitIgnore] No modification. All entries already present"
    else
        log "[GitIgnore] Added $added_count new entries to .gitignore"
    fi
}

################################################################################
# AUTO-DETECT NETWORK INTERFACES
################################################################################
detect_interfaces() {
    log "[Detect] Auto-detecting network interfaces..."

    # Detect WAN (interface with default route)
    local wan_auto=$(ip route | grep default | awk '{print $5}' | head -n1)

    # Detect LAN (first Ethernet interface that's not WAN)
    local lan_auto=$(ip link | grep -E '^[0-9]+: eth' | awk -F': ' '{print $2}' | grep -v "$wan_auto" | head -n1)

    # Detect WiFi AP-capable (first wireless interface that's not WAN)
    local wifi_auto=$(iw dev | grep Interface | awk '{print $2}' | grep -v "$wan_auto" | head -n1)

    log "[Detect] Auto-detected interfaces:"
    log "[Detect]   WAN: ${wan_auto:-not found}"
    log "[Detect]   LAN: ${lan_auto:-not found}"
    log "[Detect]   WIFI: ${wifi_auto:-not found}"

    # Use auto-detected values if not already set by user
    if [ -z "$WAN_IF_OVERRIDE" ] && [ -n "$wan_auto" ]; then
        WAN_IF="$wan_auto"
        log "[Detect] Using auto-detected WAN interface: $WAN_IF"
    fi

    if [ -z "$LAN_IF_OVERRIDE" ] && [ -n "$lan_auto" ]; then
        LAN_IF="$lan_auto"
        log "[Detect] Using auto-detected LAN interface: $LAN_IF"
    fi

    if [ -z "$WIFI_IF_OVERRIDE" ] && [ -n "$wifi_auto" ]; then
        WIFI_IF="$wifi_auto"
        log "[Detect] Using auto-detected WIFI interface: $WIFI_IF"
    fi
}

################################################################################
# BACKUP CURRENT SYSTEM STATE (CAPTURE MODE ONLY)
################################################################################
backup_system_state() {
    if [ "$MODE" != "capture" ]; then
        log "[Backup] Skipped (router mode - no backup needed)"
        return 0
    fi

    log "[Backup] (1/9) Saving current system state"

    # Create temporary directory for state files
    local temp_backup_dir="/tmp/mitm-backup-${TIMESTAMP}"
    mkdir -p "$temp_backup_dir"

    # Save IP forwarding state
    log "[Backup] (2/9) Saving IP forwarding configuration"
    sysctl net.ipv4.ip_forward > "${temp_backup_dir}/ip_forward.txt"

    # Save IPv6 state
    log "[Backup] (3/9) Saving IPv6 configuration"
    sysctl net.ipv6.conf.all.disable_ipv6 > "${temp_backup_dir}/ipv6_all.txt"
    sysctl net.ipv6.conf.default.disable_ipv6 > "${temp_backup_dir}/ipv6_default.txt"

    # Save current iptables rules
    log "[Backup] (4/9) Saving iptables rules"
    iptables-save > "${temp_backup_dir}/iptables.rules"
    iptables -t nat -S > "${temp_backup_dir}/iptables_nat.rules"

    # Save network interface configuration
    log "[Backup] (5/9) Saving network interface states"
    ip addr show > "${temp_backup_dir}/interfaces.txt"
    ip route show > "${temp_backup_dir}/routes.txt"

    # Save LAN interface configuration
    log "[Backup] (6/9) Saving ${LAN_IF} configuration"
    ip addr show dev "$LAN_IF" > "${temp_backup_dir}/lan_config.txt" 2>/dev/null || echo "No config" > "${temp_backup_dir}/lan_config.txt"

    # Save WiFi interface configuration
    log "[Backup] (7/9) Saving ${WIFI_IF} configuration"
    ip addr show dev "$WIFI_IF" > "${temp_backup_dir}/wifi_config.txt" 2>/dev/null || echo "No config" > "${temp_backup_dir}/wifi_config.txt"

    # Save DNS configuration
    log "[Backup] (8/9) Saving DNS configuration"
    cp /etc/resolv.conf "${temp_backup_dir}/resolv.conf" 2>/dev/null || touch "${temp_backup_dir}/resolv.conf"

    # Create archive
    log "[Backup] (9/9) Creating backup archive"
    tar -czf "$STATE_BACKUP" -C "$temp_backup_dir" .

    # Save backup location and WiFi state to state file
    echo "BACKUP_FILE=${STATE_BACKUP}" > "$STATE_FILE"
    echo "DNSMASQ_PID_FILE=${DNSMASQ_PID}" >> "$STATE_FILE"
    echo "DNSMASQ_CONF_FILE=${DNSMASQ_CONF}" >> "$STATE_FILE"
    echo "HOSTAPD_PID_FILE=${HOSTAPD_PID}" >> "$STATE_FILE"
    echo "HOSTAPD_CONF_FILE=${HOSTAPD_CONF}" >> "$STATE_FILE"
    echo "WIFI_ENABLED=${WIFI_ENABLED}" >> "$STATE_FILE"
    echo "WIFI_IF=${WIFI_IF}" >> "$STATE_FILE"

    # Cleanup temporary directory
    rm -rf "$temp_backup_dir"

    log "[Backup] System state backed up to: ${STATE_BACKUP}"
}

################################################################################
# RESTORE SYSTEM STATE
################################################################################
restore_system_state() {
    log "[Restore] (1/12) Restoring system to initial state"

    # Check if state file exists
    if [ ! -f "$STATE_FILE" ]; then
        log "[Restore] Warning: No state file found, performing manual restore"
        manual_restore
        cleanup_temp_files
        return
    fi

    # Load state file
    source "$STATE_FILE"

    # Stop hostapd if it was running
    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[Restore] (2/12) Stopping hostapd service"
        if [ -f "$HOSTAPD_PID_FILE" ]; then
            if kill "$(cat "$HOSTAPD_PID_FILE")" 2>/dev/null; then
                log "[Restore] hostapd stopped successfully"
            fi
            rm -f "$HOSTAPD_PID_FILE"
        else
            pkill -f "hostapd.*${TIMESTAMP}" 2>/dev/null || true
        fi

        # Remove hostapd configuration
        log "[Restore] (3/12) Removing hostapd configuration"
        rm -f "$HOSTAPD_CONF_FILE"

        # Bring down WiFi interface
        log "[Restore] (4/12) Bringing down ${WIFI_IF}"
        ip link set "$WIFI_IF" down 2>/dev/null || true
    else
        log "[Restore] (2/12) WiFi was disabled, skipping hostapd cleanup"
        log "[Restore] (3/12) Skipped"
        log "[Restore] (4/12) Skipped"
    fi

    # Stop dnsmasq if running
    log "[Restore] (5/12) Stopping dnsmasq service"
    if [ -f "$DNSMASQ_PID_FILE" ]; then
        if kill "$(cat "$DNSMASQ_PID_FILE")" 2>/dev/null; then
            log "[Restore] dnsmasq stopped successfully"
        fi
        rm -f "$DNSMASQ_PID_FILE"
    else
        pkill -f "dnsmasq.*sourcesvr.*${TIMESTAMP}" 2>/dev/null || true
    fi

    # Remove dnsmasq configuration
    log "[Restore] (6/12) Removing dnsmasq configuration"
    rm -f "$DNSMASQ_CONF_FILE"

    # Extract backup
    if [ -f "$BACKUP_FILE" ]; then
        log "[Restore] (7/12) Extracting backup archive"
        local temp_restore_dir="/tmp/mitm-restore-${TIMESTAMP}"
        mkdir -p "$temp_restore_dir"
        tar -xzf "$BACKUP_FILE" -C "$temp_restore_dir"

        # Restore iptables rules
        log "[Restore] (8/12) Restoring iptables rules"
        if iptables-restore < "${temp_restore_dir}/iptables.rules" 2>/dev/null; then
            log "[Restore] iptables rules restored successfully"
        else
            log "[Restore] Warning: Could not restore iptables rules, performing manual flush"
            iptables -F
            iptables -t nat -F
            iptables -X
        fi

        # Restore IP forwarding
        log "[Restore] (9/12) Restoring IP forwarding state"
        local ip_forward_value=$(grep -oP 'net.ipv4.ip_forward = \K\d+' "${temp_restore_dir}/ip_forward.txt")
        sysctl -w net.ipv4.ip_forward="$ip_forward_value" >/dev/null

        # Restore IPv6 settings
        log "[Restore] (10/12) Restoring IPv6 configuration"
        local ipv6_all=$(grep -oP 'net.ipv6.conf.all.disable_ipv6 = \K\d+' "${temp_restore_dir}/ipv6_all.txt")
        local ipv6_default=$(grep -oP 'net.ipv6.conf.default.disable_ipv6 = \K\d+' "${temp_restore_dir}/ipv6_default.txt")
        sysctl -w net.ipv6.conf.all.disable_ipv6="$ipv6_all" >/dev/null
        sysctl -w net.ipv6.conf.default.disable_ipv6="$ipv6_default" >/dev/null

        # Flush and restore LAN interface
        log "[Restore] (11/12) Restoring ${LAN_IF} interface"
        ip addr flush dev "$LAN_IF" 2>/dev/null || true
        ip link set "$LAN_IF" down 2>/dev/null || true

        # Cleanup
        log "[Restore] (12/12) Cleaning up temporary files"
        rm -rf "$temp_restore_dir"
    else
        log "[Restore] Warning: Backup file not found, performing manual cleanup"
        manual_restore
    fi

    # Cleanup all temporary files
    cleanup_temp_files

    log "[Restore] System successfully restored to initial state"
}

################################################################################
# MANUAL RESTORE (FALLBACK)
################################################################################
manual_restore() {
    log "[Manual Restore] Performing manual system restore"

    # Stop any running hostapd instances
    log "[Manual Restore] Stopping hostapd"
    pkill hostapd 2>/dev/null || true

    # Stop any running dnsmasq instances
    log "[Manual Restore] Stopping dnsmasq"
    pkill dnsmasq 2>/dev/null || true

    # Flush iptables
    iptables -F
    iptables -t nat -F
    iptables -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT

    # Disable IP forwarding
    sysctl -w net.ipv4.ip_forward=0 >/dev/null

    # Re-enable IPv6
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null

    # Re-enable IPv6 on specific interfaces
    sysctl -w net.ipv6.conf."${LAN_IF}".disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf."${WAN_IF}".disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf."${WIFI_IF}".disable_ipv6=0 >/dev/null 2>&1 || true

    # Reset IPv6 iptables
    ip6tables -P INPUT ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true

    # Flush LAN interface
    ip addr flush dev "$LAN_IF" 2>/dev/null || true
    ip link set "$LAN_IF" down 2>/dev/null || true

    # Flush WiFi interface
    ip addr flush dev "$WIFI_IF" 2>/dev/null || true
    ip link set "$WIFI_IF" down 2>/dev/null || true

    log "[Manual Restore] Manual restore completed"
}

################################################################################
# CLEANUP TEMPORARY FILES
################################################################################
cleanup_temp_files() {
    log "[Cleanup] Removing temporary files"

    [ -f "$STATE_FILE" ] && rm -f "$STATE_FILE" && log "[Cleanup] Removed: $STATE_FILE"
    [ -f "$DNSMASQ_CONF" ] && rm -f "$DNSMASQ_CONF" && log "[Cleanup] Removed: $DNSMASQ_CONF"
    [ -f "$DNSMASQ_PID" ] && rm -f "$DNSMASQ_PID" && log "[Cleanup] Removed: $DNSMASQ_PID"
    [ -f "$HOSTAPD_CONF" ] && rm -f "$HOSTAPD_CONF" && log "[Cleanup] Removed: $HOSTAPD_CONF"
    [ -f "$HOSTAPD_PID" ] && rm -f "$HOSTAPD_PID" && log "[Cleanup] Removed: $HOSTAPD_PID"

    log "[Cleanup] Done"
}

################################################################################
# CONFIGURE WIFI HOTSPOT
################################################################################
configure_wifi_hotspot() {
    log "[WiFi] (1/4) Configuring WiFi hotspot on ${WIFI_IF}"

    # Check if WiFi interface exists
    if ! ip link show "$WIFI_IF" &>/dev/null; then
        log "[WiFi] Error: WiFi interface $WIFI_IF not found"
        return 1
    fi

    # Determine IEEE standards based on band
    log "[WiFi] (2/4) Configuring ${WIFI_IF} for ${WIFI_BAND} band ($([ "$WIFI_BAND" = "a" ] && echo "5GHz" || echo "2.4GHz"))"
    local ieee80211n="1"
    local ieee80211ac="0"

    if [ "$WIFI_BAND" = "a" ]; then
        ieee80211ac="1"  # Enable 802.11ac for 5GHz
    fi

    # Create hostapd configuration
    log "[WiFi] (3/4) Creating hostapd configuration"
    cat > "$HOSTAPD_CONF" <<EOF
# hostapd configuration for MITM WiFi hotspot (MAX THROUGHPUT - ${WIFI_BAND} ${WIFI_CHANNEL}MHz)
interface=${WIFI_IF}
driver=nl80211
ssid=${WIFI_SSID}
hw_mode=${WIFI_BAND}
channel=${WIFI_CHANNEL}
country_code=${WIFI_COUNTRY}

# 802.11n settings (HT - High Throughput)
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][MAX-AMSDU-7935]

# 802.11ac settings (VHT - Very High Throughput) for 5GHz
ieee80211ac=1
vht_capab=[MAX-MPDU-11454][SHORT-GI-80][MAX-A-MPDU-LEN-EXP7]
vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42

# WMM (Wi-Fi Multimedia) for QoS
wmm_enabled=1

# Security: WPA2-PSK (CCMP)
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=${WIFI_PASSWORD}

# Additional settings
macaddr_acl=0
ignore_broadcast_ssid=0

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
EOF

    # Start hostapd
    log "[WiFi] (4/4) Starting hostapd"
    if hostapd -B -P "$HOSTAPD_PID" "$HOSTAPD_CONF" 2>&1 | tee -a "$LOGFILE"; then
        log "[WiFi] hostapd started successfully"
        sleep 2  # Give hostapd time to initialize
        return 0
    else
        log "[WiFi] Error: Failed to start hostapd"
        return 1
    fi
}

################################################################################
# VERIFY MITM STATUS (POST-STARTUP HEALTHCHECK)
################################################################################
verify_mitm_status() {
    log "[Verify] Running post-startup healthchecks..."

    local errors=0

    # Check 1: IP forwarding
    if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
        log "[Verify] ✗ IP forwarding not enabled"
        ((errors++))
    else
        log "[Verify] ✓ IP forwarding enabled"
    fi

    # Check 2: NAT rule exists
    if ! iptables -t nat -S | grep -q MASQUERADE; then
        log "[Verify] ✗ NAT MASQUERADE rule missing"
        ((errors++))
    else
        log "[Verify] ✓ NAT MASQUERADE rule present"
    fi

    # Check 3: dnsmasq running
    if [ ! -f "$DNSMASQ_PID" ] || ! kill -0 "$(cat "$DNSMASQ_PID")" 2>/dev/null; then
        log "[Verify] ✗ dnsmasq not running"
        ((errors++))
    else
        log "[Verify] ✓ dnsmasq running (PID: $(cat "$DNSMASQ_PID"))"
    fi

    # Check 4: hostapd running (if WiFi enabled)
    if [ "$WIFI_ENABLED" = "true" ]; then
        if [ ! -f "$HOSTAPD_PID" ] || ! kill -0 "$(cat "$HOSTAPD_PID")" 2>/dev/null; then
            log "[Verify] ✗ hostapd not running"
            ((errors++))
        else
            log "[Verify] ✓ hostapd running (PID: $(cat "$HOSTAPD_PID"))"
        fi
    fi

    # Check 5: LAN interface has IP
    if ! ip addr show dev "$LAN_IF" | grep -q "$LAN_IP"; then
        log "[Verify] ✗ LAN interface $LAN_IF missing IP $LAN_IP"
        ((errors++))
    else
        log "[Verify] ✓ LAN interface configured"
    fi

    # Check 6: WiFi interface has IP (if enabled)
    if [ "$WIFI_ENABLED" = "true" ]; then
        if ! ip addr show dev "$WIFI_IF" | grep -q "$WIFI_IP"; then
            log "[Verify] ✗ WiFi interface $WIFI_IF missing IP $WIFI_IP"
            ((errors++))
        else
            log "[Verify] ✓ WiFi interface configured"
        fi
    fi

    # Check 7: IPv6 is disabled
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" != "1" ]; then
        log "[Verify] ✗ IPv6 not disabled"
        ((errors++))
    else
        log "[Verify] ✓ IPv6 disabled"
    fi

    if [ $errors -eq 0 ]; then
        log "[Verify] ✓ All checks passed - MITM is operational"
        return 0
    else
        log "[Verify] ✗ $errors checks failed - MITM may not work correctly"
        return 1
    fi
}

################################################################################
# SHOW TRAFFIC STATISTICS
################################################################################
show_traffic_stats() {
    log "[Stats] ===== Current Traffic Statistics ====="

    log "[Stats] Ethernet Interface (${LAN_IF}):"
    ip -s link show "$LAN_IF" 2>/dev/null || log "[Stats] Interface not found"

    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[Stats] "
        log "[Stats] WiFi Interface (${WIFI_IF}):"
        ip -s link show "$WIFI_IF" 2>/dev/null || log "[Stats] Interface not found"
    fi

    log "[Stats] "
    log "[Stats] Active DHCP Leases:"
    if [ -f /var/lib/misc/dnsmasq.leases ]; then
        cat /var/lib/misc/dnsmasq.leases
    else
        log "[Stats] No active leases"
    fi

    log "[Stats] "
    log "[Stats] Current iptables NAT rules:"
    iptables -t nat -S

    log "[Stats] ================================"
}

################################################################################
# EXPORT CONFIGURATION TO JSON
################################################################################
export_config_json() {
    local json_file="${RESULTS_DIR}/mitm-config-${TIMESTAMP}.json"

    cat > "$json_file" <<EOF
{
  "version": "${VERSION}",
  "timestamp": "$(date -Iseconds)",
  "interfaces": {
    "lan": "$LAN_IF",
    "wan": "$WAN_IF",
    "wifi": "$WIFI_IF"
  },
  "network": {
    "lan_ip": "$LAN_IP",
    "lan_netmask": "$LAN_NETMASK",
    "wifi_ip": "$WIFI_IP",
    "wifi_netmask": "$WIFI_NETMASK",
    "dhcp_range_ethernet": "${DHCP_RANGE_START}-${DHCP_RANGE_END}",
    "dhcp_range_wifi": "${WIFI_DHCP_START}-${WIFI_DHCP_END}",
    "dhcp_lease_time": "$DHCP_LEASE_TIME"
  },
  "wifi": {
    "enabled": $WIFI_ENABLED,
    "ssid": "$WIFI_SSID",
    "band": "$WIFI_BAND",
    "channel": $WIFI_CHANNEL,
    "country": "$WIFI_COUNTRY"
  },
  "files": {
    "log": "$LOGFILE",
    "backup": "$STATE_BACKUP",
    "dnsmasq_conf": "$DNSMASQ_CONF",
    "hostapd_conf": "$HOSTAPD_CONF"
  }
}
EOF

    log "[Export] Configuration exported to: $json_file"
}

################################################################################
# START MITM CONFIGURATION
################################################################################
start_mitm() {
    log "[MITM] ===== Starting MITM Configuration (${MODE} mode) ====="

    # Backup current state first (only in capture mode)
    backup_system_state

    # Save configuration to file (router mode only)
    if [ "$MODE" = "router" ]; then
        save_config
    fi

    # Step 1: Flush iptables
    log "[MITM] (1/12) Flushing iptables rules"
    iptables -F
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -t nat -F
    iptables -X
    log "[MITM] iptables flushed successfully"

    # Step 2: Disable IPv6
    log "[MITM] (2/12) Disabling IPv6 completely to prevent leaks"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null

    # Disable IPv6 on specific interfaces
    sysctl -w net.ipv6.conf."${LAN_IF}".disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf."${WAN_IF}".disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf."${WIFI_IF}".disable_ipv6=1 >/dev/null 2>&1 || true

    # Block IPv6 traffic in iptables
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P OUTPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true

    log "[MITM] IPv6 completely disabled (sysctl + ip6tables)"

    # Step 3: Enable IP forwarding
    log "[MITM] (3/12) Enabling IP forwarding"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    log "[MITM] IP forwarding enabled"

    # Step 4: Configure LAN interface (Ethernet)
    log "[MITM] (4/12) Configuring LAN interface ${LAN_IF}"
    ip addr flush dev "$LAN_IF"
    ip addr add "${LAN_IP}/${LAN_NETMASK}" dev "$LAN_IF"
    ip link set "$LAN_IF" up
    nmcli dev set "$LAN_IF" managed no 2>/dev/null || true
    log "[MITM] ${LAN_IF} configured with IP ${LAN_IP}/${LAN_NETMASK}"

    # Step 5: Configure WiFi interface and hotspot (if enabled)
    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM] (5/12) Configuring WiFi interface ${WIFI_IF}"

        # Assign DIFFERENT IP to WiFi interface
        log "[MITM] Assigning IP ${WIFI_IP}/${WIFI_NETMASK} to ${WIFI_IF}"
        ip addr flush dev "$WIFI_IF" 2>/dev/null || true
        ip addr add "${WIFI_IP}/${WIFI_NETMASK}" dev "$WIFI_IF"
        ip link set "$WIFI_IF" up
        nmcli dev set "$WIFI_IF" managed no 2>/dev/null || true

        # Now configure WiFi hotspot (hostapd)
        if configure_wifi_hotspot; then
            log "[MITM] WiFi hotspot configured successfully"
        else
            log "[MITM] ERROR: WiFi hotspot configuration failed"
            log "[MITM] Check: iw list, dmesg, and hostapd logs"
            log "[MITM] Continuing with Ethernet only..."
            WIFI_ENABLED="false"
            ip addr flush dev "$WIFI_IF" 2>/dev/null || true
            ip link set "$WIFI_IF" down 2>/dev/null || true
        fi
    else
        log "[MITM] (5/12) WiFi hotspot disabled, skipping"
    fi

    # Step 6: Get WAN DNS servers
    log "[MITM] (6/12) Using Cloudflare DNS servers"
    local wan_dns_primary="1.1.1.1"
    local wan_dns_secondary="1.0.0.1"

    log "[MITM] DNS servers configured: Primary=$wan_dns_primary, Secondary=$wan_dns_secondary"

    # Step 7: Configure iptables NAT for internet traffic
    log "[MITM] (7/12) Configuring NAT rules for internet traffic"
    iptables -P FORWARD ACCEPT
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

    # Allow forwarding from LAN to WAN
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
    iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow forwarding from WiFi to WAN (if WiFi enabled)
    if [ "$WIFI_ENABLED" = "true" ]; then
        iptables -A FORWARD -i "$WIFI_IF" -o "$WAN_IF" -j ACCEPT
        iptables -A FORWARD -i "$WAN_IF" -o "$WIFI_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT
    fi

    log "[MITM] NAT rules configured"

    # Step 8: Configure DNS routing (optional - dnsmasq now handles DNS)
    log "[MITM] (8/12) DNS will be handled by dnsmasq (forwarding to ${wan_dns_primary})"

    # Note: DNS DNAT rules are no longer needed as dnsmasq is listening on port 53
    # and forwarding DNS requests to the WAN DNS servers directly
    # The client devices will use the gateway IP (LAN_IP/WIFI_IP) as their DNS server

    log "[MITM] DNS requests from clients will be processed by dnsmasq and forwarded to ${wan_dns_primary}"

    # Step 9: Create dnsmasq configuration for DHCP
    log "[MITM] (9/12) Creating dnsmasq DHCP configuration"

cat > "$DNSMASQ_CONF" <<EOF
# dnsmasq configuration for MITM capture (DHCP + DNS server)
interface=${LAN_IF}
interface=${WIFI_IF}
bind-interfaces

# DHCP for Ethernet (eth1)
dhcp-range=interface:${LAN_IF},${DHCP_RANGE_START},${DHCP_RANGE_END},${DHCP_LEASE_TIME}
dhcp-option=interface:${LAN_IF},3,${LAN_IP}
dhcp-option=interface:${LAN_IF},6,${LAN_IP}

# DHCP for WiFi (wlan1)
dhcp-range=interface:${WIFI_IF},${WIFI_DHCP_START},${WIFI_DHCP_END},${DHCP_LEASE_TIME}
dhcp-option=interface:${WIFI_IF},3,${WIFI_IP}
dhcp-option=interface:${WIFI_IF},6,${WIFI_IP}

# DNS configuration
port=53
server=${wan_dns_primary}
server=${wan_dns_secondary}
no-resolv

# Disable IPv6
listen-address=${LAN_IP}
listen-address=${WIFI_IP}

log-queries
log-dhcp
EOF

    log "[MITM] dnsmasq configuration created (DHCP + DNS on eth1${WIFI_ENABLED:+ and wlan1})"

    # Step 10: Start dnsmasq
    log "[MITM] (10/12) Starting dnsmasq DHCP server"
    if dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file="$DNSMASQ_PID" 2>&1 | tee -a "$LOGFILE"; then
        log "[MITM] dnsmasq started successfully"
    else
        log "[MITM] Error: Failed to start dnsmasq"
        restore_system_state
        exit 1
    fi

    # Step 11: Verify WiFi hotspot status
    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM] (11/12) Verifying WiFi hotspot status"
        if [ -f "$HOSTAPD_PID" ] && kill -0 "$(cat "$HOSTAPD_PID")" 2>/dev/null; then
            log "[MITM] WiFi hotspot is running (PID: $(cat "$HOSTAPD_PID"))"
        else
            log "[MITM] Warning: WiFi hotspot may not be running properly"
        fi
    else
        log "[MITM] (11/12) WiFi hotspot disabled, skipping verification"
    fi

    # Step 12: Display summary
    log "[MITM] (12/12) Configuration complete"
    log "[MITM] ===== MITM Setup Summary ====="
    log "[MITM] LAN Interface (Ethernet): ${LAN_IF} (${LAN_IP}/${LAN_NETMASK})"

    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM] "
        log "[MITM] WiFi Hotspot Configuration:"
        log "[MITM]   Interface: ${WIFI_IF}"
        log "[MITM]   SSID: ${WIFI_SSID}"
        log "[MITM]   Password: **********"
        log "[MITM]   Band: ${WIFI_BAND} ($([ "$WIFI_BAND" = "a" ] && echo "5GHz" || echo "2.4GHz"))"
        log "[MITM]   Channel: ${WIFI_CHANNEL}"
        log "[MITM]   Country: ${WIFI_COUNTRY}"
        log "[MITM]   Security: WPA2-PSK (CCMP/AES)"
    else
        log "[MITM] WiFi Hotspot: Disabled"
    fi

    log "[MITM] "
    log "[MITM] WAN Interface: ${WAN_IF}"
    log "[MITM] DHCP Range (Ethernet): ${DHCP_RANGE_START} - ${DHCP_RANGE_END}"
    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM] DHCP Range (WiFi): ${WIFI_DHCP_START} - ${WIFI_DHCP_END}"
    fi
    log "[MITM] DHCP Lease Time: ${DHCP_LEASE_TIME}"
    log "[MITM] DNS Server: dnsmasq on gateway (forwarding to ${wan_dns_primary})"
    log "[MITM] "
    log "[MITM] Next steps:"
    log "[MITM] 1. Connect SOURCESVR device via:"
    log "[MITM]    - Ethernet: Connect to ${LAN_IF} port"

    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM]    - WiFi: Connect to SSID '${WIFI_SSID}'"
    fi

    log "[MITM] 2. Device will receive IP via DHCP"
    log "[MITM] 3. Start Wireshark: wireshark -i ${LAN_IF} -k"

    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM]    (or wireshark -i ${WIFI_IF} -k for WiFi traffic)"
    fi

    log "[MITM] 4. Apply Wireshark filter: ip.addr == <SOURCESVR_IP> && http"
    log "[MITM] "
    log "[MITM] To check DHCP leases: cat /var/lib/misc/dnsmasq.leases"
    log "[MITM] To view statistics: $0 --stats"
    log "[MITM] To stop and restore: $0 --stop"
    log "[MITM] ================================"

    # Export configuration to JSON
    export_config_json

    # Run post-startup verification
    log "[MITM] "
    verify_mitm_status
}

################################################################################
# CHECK PREREQUISITES
################################################################################
check_prerequisites() {
    log "[Prerequisites] Checking system requirements"
    local missing_tools=()
    local missing_packages=()

    # Check for required commands
    for cmd in iptables ip sysctl dnsmasq hostapd; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_tools+=("$cmd")
            log "[Prerequisites] ✗ Missing: $cmd"
            # Map command to package name
            case $cmd in
                iptables)
                    missing_packages+=("iptables")
                    ;;
                ip)
                    missing_packages+=("iproute2")
                    ;;
                sysctl)
                    missing_packages+=("procps")
                    ;;
                dnsmasq)
                    missing_packages+=("dnsmasq")
                    ;;
                hostapd)
                    missing_packages+=("hostapd")
                    ;;
            esac
        else
            log "[Prerequisites] ✓ Found: $cmd"
        fi
    done

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        log "[Prerequisites] ✗ Error: This script must be run as root"
        echo "Please run with sudo or as root user"
        exit 1
    else
        log "[Prerequisites] ✓ Running as root"
    fi

    # Check network interfaces
    if ! ip link show "$LAN_IF" &>/dev/null; then
        log "[Prerequisites] ✗ Error: Interface $LAN_IF not found"
        missing_tools+=("$LAN_IF interface")
    else
        log "[Prerequisites] ✓ Interface $LAN_IF exists"
    fi

    if ! ip link show "$WAN_IF" &>/dev/null; then
        log "[Prerequisites] ✗ Error: Interface $WAN_IF not found"
        missing_tools+=("$WAN_IF interface")
    else
        log "[Prerequisites] ✓ Interface $WAN_IF exists"
    fi

    if [ "$WIFI_ENABLED" = "true" ]; then
        if ! ip link show "$WIFI_IF" &>/dev/null; then
            log "[Prerequisites] ✗ Warning: WiFi interface $WIFI_IF not found (WiFi will be disabled)"
        else
            log "[Prerequisites] ✓ Interface $WIFI_IF exists"
        fi
    fi

    # Display missing requirements and installation info
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log "[Prerequisites] ================================"
        log "[Prerequisites] Missing requirements: ${missing_tools[*]}"
        if [ ${#missing_packages[@]} -gt 0 ]; then
            log "[Prerequisites] "
            log "[Prerequisites] The following packages can be installed via --install:"
            for pkg in "${missing_packages[@]}"; do
                log "[Prerequisites] - $pkg"
            done
            log "[Prerequisites] "
            log "[Prerequisites] To install missing packages, run:"
            log "[Prerequisites] sudo $0 --install"
            log "[Prerequisites] "
            # Detect package manager and show manual command
            if command -v apt-get &>/dev/null; then
                log "[Prerequisites] Or manually install with:"
                log "[Prerequisites] sudo apt-get update"
                log "[Prerequisites] sudo apt-get install -y ${missing_packages[*]}"
            elif command -v yum &>/dev/null; then
                log "[Prerequisites] Or manually install with:"
                log "[Prerequisites] sudo yum install -y ${missing_packages[*]}"
            fi
        fi
        log "[Prerequisites] ================================"
        return 1
    fi

    log "[Prerequisites] ✓ All prerequisites satisfied"
    return 0
}

################################################################################
# INSTALL PREREQUISITES
################################################################################
install_prerequisites() {
    log "[Install] Checking what needs to be installed"
    local packages_to_install=()

    # Check which commands are missing
    if ! command -v iptables &>/dev/null; then
        packages_to_install+=("iptables")
    fi
    if ! command -v ip &>/dev/null; then
        packages_to_install+=("iproute2")
    fi
    if ! command -v sysctl &>/dev/null; then
        packages_to_install+=("procps")
    fi
    if ! command -v dnsmasq &>/dev/null; then
        packages_to_install+=("dnsmasq")
    fi
    if ! command -v hostapd &>/dev/null; then
        packages_to_install+=("hostapd")
    fi

    # Create runs directory if it doesn't exist
    if [ ! -d "$RUNS_DIR" ]; then
        log "[Install] Creating runs directory: $RUNS_DIR"
        mkdir -p "$RUNS_DIR"
    else
        log "[Install] Runs directory already exists: $RUNS_DIR"
    fi

    # If nothing to install, exit early
    if [ ${#packages_to_install[@]} -eq 0 ]; then
        log "[Install] All prerequisites are already installed"
        log "[Install] Runs directory verified"
        return 0
    fi

    # Display what will be installed
    log "[Install] The following packages will be installed: ${packages_to_install[*]}"

    # Install based on package manager
    if command -v apt-get &>/dev/null; then
        log "[Install] Using apt-get package manager"
        log "[Install] Updating package lists..."
        apt-get update
        log "[Install] Installing packages..."
        apt-get install -y "${packages_to_install[@]}"
    elif command -v yum &>/dev/null; then
        log "[Install] Using yum package manager"
        log "[Install] Installing packages..."
        yum install -y "${packages_to_install[@]}"
    else
        log "[Install] Error: No supported package manager found"
        exit 1
    fi

    log "[Install] Prerequisites installed successfully"
    log "[Install] Runs directory ready: $RUNS_DIR"
}

################################################################################
# DISPLAY HELP
################################################################################
show_help() {
    cat <<EOF
================================================================================
MITM SOURCESVR Traffic Capture Script with WiFi Hotspot
================================================================================
Author: Bruno DELNOZ
Email: bruno.delnoz@protonmail.com
Version: ${VERSION}
Script: ${SCRIPT_NAME}

DESCRIPTION:
    Configure Linux as a Man-In-The-Middle router to capture and analyze
    network traffic from SOURCESVR devices.

    This script:
    - Creates a reversible MITM network setup
    - Routes SOURCESVR traffic through this machine via Ethernet OR WiFi
    - Enables full packet capture with Wireshark
    - Provides WiFi hotspot (5GHz by default) for wireless MITM
    - Provides DHCP service for automatic IP assignment
    - Routes DNS queries transparently to WAN DNS servers
    - Backs up all system state before modifications

USAGE:
    sudo ./${SCRIPT_NAME} [OPTIONS]

REQUIRED ARGUMENTS:
    --exec, -exe         Execute MITM configuration
    --start, -sta        Same as --exec (alias)
    --stop, -sto         Stop MITM and restore system state

MODE SELECTION:
    --router             Router mode (default) - permanent, minimal logs, no backup
    --capture            Capture mode - verbose logs, system backup, analysis

    Note: If no mode is specified, --router is used by default

SYSTEMD SERVICE:
    --install-service    Install as systemd service (auto-start on boot)
    --uninstall-service  Remove systemd service

OPTIONAL ARGUMENTS:
    --help, -h           Display this help message (default if no args)
    --prerequis, -pr     Check prerequisites only
    --install, -i        Install missing prerequisites
    --simulate, -s       Simulate execution (dry-run)
    --stats              Show current traffic statistics
    --changelog, -ch     Display full changelog
    --auto-detect        Auto-detect network interfaces

NETWORK CONFIGURATION OPTIONS:
    --lan-if <if>        LAN interface name (default: ${LAN_IF})
    --wan-if <if>        WAN interface name (default: ${WAN_IF})
    --lan-ip <ip>        LAN gateway IP address (default: ${LAN_IP})
    --lan-netmask <mask> LAN netmask in CIDR (default: ${LAN_NETMASK})
    --dhcp-range <range> DHCP IP range (default: ${DHCP_RANGE_START}-${DHCP_RANGE_END})

WIFI HOTSPOT CONFIGURATION OPTIONS:
    --wifi-disable       Disable WiFi hotspot (Ethernet only)
    --wifi-if <if>       WiFi interface name (default: ${WIFI_IF})
    --wifi-ssid <ssid>   WiFi SSID (default: ${WIFI_SSID})
    --wifi-pass <pass>   WiFi password (default: ${WIFI_PASSWORD})
    --wifi-band <a|g>    WiFi band: a=5GHz, g=2.4GHz (default: ${WIFI_BAND})
    --wifi-channel <ch>  WiFi channel (default: ${WIFI_CHANNEL})
    --wifi-country <cc>  Country code (default: ${WIFI_COUNTRY})

CONFIGURATION (Current Defaults):
    LAN Interface: ${LAN_IF}
    WAN Interface: ${WAN_IF}
    LAN IP: ${LAN_IP}/${LAN_NETMASK}
    DHCP Range (Ethernet): ${DHCP_RANGE_START} - ${DHCP_RANGE_END}

    WiFi Hotspot: $([ "$WIFI_ENABLED" = "true" ] && echo "ENABLED" || echo "DISABLED")
    WiFi Interface: ${WIFI_IF}
    WiFi SSID: ${WIFI_SSID}
    WiFi Password: ${WIFI_PASSWORD}
    WiFi Band: ${WIFI_BAND} ($([ "$WIFI_BAND" = "a" ] && echo "5GHz" || echo "2.4GHz"))
    WiFi Channel: ${WIFI_CHANNEL}
    WiFi Country: ${WIFI_COUNTRY}
    DNS: Auto-detected from system

EXAMPLES:
    # Display help
    ./${SCRIPT_NAME} --help

    # Check prerequisites
    sudo ./${SCRIPT_NAME} --prerequis

    # Install missing packages
    sudo ./${SCRIPT_NAME} --install

    # Start in ROUTER mode (default - permanent, minimal logs)
    sudo ./${SCRIPT_NAME} --exec
    sudo ./${SCRIPT_NAME} --router --exec

    # Start in CAPTURE mode (verbose logs, backup system state)
    sudo ./${SCRIPT_NAME} --capture --exec

    # Install as systemd service (auto-start on boot)
    sudo ./${SCRIPT_NAME} --install-service
    sudo systemctl enable mitm-router
    sudo systemctl start mitm-router

    # Check service status
    sudo systemctl status mitm-router

    # Uninstall systemd service
    sudo ./${SCRIPT_NAME} --uninstall-service

    # Auto-detect interfaces and start
    sudo ./${SCRIPT_NAME} --auto-detect --exec

    # Start with Ethernet only (WiFi disabled)
    sudo ./${SCRIPT_NAME} --exec --wifi-disable

    # Start with custom WiFi SSID and password
    sudo ./${SCRIPT_NAME} --exec --wifi-ssid "MyMITM" --wifi-pass "MySecurePass123"

    # Show traffic statistics
    sudo ./${SCRIPT_NAME} --stats

    # Stop MITM and restore system
    sudo ./${SCRIPT_NAME} --stop

FILES CREATED:
    Config: ${SCRIPT_DIR}/mitm-router.conf (persistent configuration)
    Logs: ${LOGS_DIR}/log.${SCRIPT_NAME}.<timestamp>.${VERSION}.log
    Runtime files: ${RUNS_DIR}/*.{pid,conf} (dnsmasq, hostapd)
    Backups (capture mode only): ${RESULTS_DIR}/system-state-backup.<timestamp>.tar.gz

ROUTER MODE vs CAPTURE MODE:
    Router Mode (default):
    - Permanent configuration
    - Minimal logging (errors only)
    - No system backup
    - Configuration saved to ./mitm-router.conf
    - Runtime files in ./runs/ (dnsmasq-router.*, hostapd-router.*)
    - Designed for daily use as home router

    Capture Mode:
    - Temporary configuration
    - Verbose logging (all operations)
    - Full system state backup
    - Runtime files in ./runs/ (dnsmasq-capture-<timestamp>.*, hostapd-capture-<timestamp>.*)
    - Designed for packet analysis and debugging

NOTES:
    - All modifications are fully reversible
    - System state is backed up before any changes
    - Use --stop to restore original configuration
    - DNS queries are forwarded to WAN DNS (not intercepted)
    - IPv6 is disabled to prevent traffic leaks
    - WiFi hotspot uses WPA2-PSK (CCMP/AES) encryption
================================================================================
EOF
}

################################################################################
# DISPLAY CHANGELOG
################################################################################
show_changelog() {
    cat <<EOF
================================================================================
CHANGELOG
================================================================================
v3.2 - 2025-02-03 - DUAL MODE: Router (default) + Capture
-----------------
- Added --router mode (default, permanent, minimal logs, no backup)
- Added --capture mode (verbose logs, system backup, analysis)
- Configuration file stored in script directory: ./mitm-router.conf
- Added systemd service installation (--install-service)
- Added --uninstall-service to remove systemd service
- Mode auto-detection: default is --router if not specified
- Logs optimized per mode (minimal for router, verbose for capture)
- Added persistent configuration loading from ./mitm-router.conf
- Runtime files (PID/config) stored in ./runs/ directory (never /tmp)
- Created ./runs/ directory for all runtime files
- Router mode: ./runs/dnsmasq-router.{conf,pid}, ./runs/hostapd-router.{conf,pid}
- Capture mode: ./runs/dnsmasq-capture-<timestamp>.{conf,pid}, etc.
- Added ./runs/ to .gitignore automatically
- --install now creates ./runs/ directory if missing
- Added save_config() and load_config() functions
- Separated file paths based on operating mode

v3.1 - 2025-02-03 - BUG FIXES & IMPROVEMENTS
-----------------
- Fixed critical duplicate --stop argument parsing
- Fixed --start/-st and --stop/-st alias conflict (now -sta and -sto)
- Added post-startup healthcheck verification (verify_mitm_status)
- Added show_traffic_stats() function for monitoring
- Added export_config_json() for configuration export
- Added auto-detection of network interfaces
- Improved error handling for hostapd/dnsmasq failures
- Added input validation for WiFi password length
- Cleaned up obsolete TODOs
- Password now hidden in summary output (shows *********)

v3.0 - 2025-01-28 - MAJOR RELEASE: Separate Subnets & Performance Optimization
-----------------
- Fixed critical dnsmasq startup issue (wlan1 needs IP before dnsmasq starts)
- Separated Ethernet and WiFi on different subnets to avoid IP conflicts
  * Ethernet (eth1): 192.168.50.0/24 (DHCP: .10-.50)
  * WiFi (wlan1): 192.168.51.0/24 (DHCP: .10-.50)
- Added new WiFi-specific configuration variables:
  * WIFI_IP, WIFI_DHCP_START, WIFI_DHCP_END
- Optimized WiFi performance with 802.11n/ac enhancements:
  * HT40 (40MHz channel width) for 2.4GHz: ~300 Mbps
  * VHT80 (80MHz channel width) for 5GHz: ~867 Mbps
  * Enabled SHORT-GI (Short Guard Interval) for better throughput
- Enhanced hostapd configuration with advanced VHT capabilities
- Added cleanup_temp_files() function for proper temporary file management
- Fixed temporary files not being removed on --stop
- Improved restore_system_state() with automatic cleanup
- Added --start alias for --exec command (both work identically)
- Both Ethernet and WiFi devices now work independently on separate subnets
- Complete error handling for WiFi hotspot failures with automatic fallback

v2.5 - 2025-01-27 - MAJOR RELEASE: Complete WiFi Hotspot Integration
-----------------
- Added WiFi hotspot capability on wlan1 (5GHz by default, dual-band support)
- WiFi hotspot ENABLED by default alongside Ethernet (eth1)
- New arguments: --wifi-disable, --wifi-if, --wifi-ssid, --wifi-pass,
                 --wifi-band, --wifi-channel, --wifi-country
- WPA2-PSK configuration (CCMP/AES) matching wlan0 WAN security
- Unified DHCP for eth1 and wlan1 via dnsmasq (shared subnet)
- hostapd integration for WiFi AP mode
- Both eth1 (Ethernet) and wlan1 (WiFi) on same subnet (192.168.50.0/24)
- Supports RTL8812BU chipset (2.4GHz and 5GHz)
- Country code set to BE (Belgium) by default
- Enhanced backup/restore for WiFi components (hostapd PID, config, etc.)
- Added hostapd to prerequisites check and install
- WiFi interface validation in prerequisites
- Improved logging with WiFi hotspot status verification
- Updated help with comprehensive WiFi configuration examples
- Complete error handling for WiFi hotspot failures
================================================================================
EOF
}

################################################################################
# MAIN EXECUTION LOGIC
################################################################################
# If no arguments provided, show help and exit
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Initialize gitignore
manage_gitignore

# Parse arguments
SIMULATE=false
ACTION=""
AUTO_DETECT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        --changelog|-ch)
            show_changelog
            exit 0
            ;;
        --prerequis|-pr)
            ACTION="check_prereq"
            shift
            ;;
        --install|-i)
            ACTION="install"
            shift
            ;;
        --exec|-exe|--start|-sta)
            ACTION="start"
            shift
            ;;
        --router)
            MODE="router"
            shift
            ;;
        --capture)
            MODE="capture"
            shift
            ;;
        --install-service)
            ACTION="install_service"
            shift
            ;;
        --uninstall-service)
            ACTION="uninstall_service"
            shift
            ;;
        --stop|-sto)
            ACTION="stop"
            shift
            ;;
        --stats)
            ACTION="stats"
            shift
            ;;
        --simulate|-s)
            SIMULATE=true
            shift
            ;;
        --auto-detect)
            AUTO_DETECT=true
            shift
            ;;
        --lan-if)
            LAN_IF="$2"
            LAN_IF_OVERRIDE=true
            shift 2
            ;;
        --wan-if)
            WAN_IF="$2"
            WAN_IF_OVERRIDE=true
            shift 2
            ;;
        --lan-ip)
            LAN_IP="$2"
            shift 2
            ;;
        --lan-netmask)
            LAN_NETMASK="$2"
            shift 2
            ;;
        --dhcp-range)
            DHCP_RANGE_START="${2%-*}"
            DHCP_RANGE_END="${2#*-}"
            shift 2
            ;;
        --wifi-disable)
            WIFI_ENABLED="false"
            shift
            ;;
        --wifi-if)
            WIFI_IF="$2"
            WIFI_IF_OVERRIDE=true
            shift 2
            ;;
        --wifi-ssid)
            WIFI_SSID="$2"
            shift 2
            ;;
        --wifi-pass)
            if [ ${#2} -lt 8 ]; then
                log "[Error] WiFi password must be at least 8 characters"
                exit 1
            fi
            WIFI_PASSWORD="$2"
            shift 2
            ;;
        --wifi-band)
            WIFI_BAND="$2"
            shift 2
            ;;
        --wifi-channel)
            WIFI_CHANNEL="$2"
            shift 2
            ;;
        --wifi-country)
            WIFI_COUNTRY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Auto-detect interfaces if requested
if [ "$AUTO_DETECT" = true ]; then
    detect_interfaces
fi

# Load configuration from file (if exists)
load_config

# Execute action based on parsed arguments
case $ACTION in
    check_prereq)
        log "===== Prerequisite Check ====="
        if check_prerequisites; then
            log "All prerequisites satisfied"
            exit 0
        else
            log "Some prerequisites are missing"
            exit 1
        fi
        ;;
    install)
        log "===== Installing Prerequisites ====="
        install_prerequisites
        ;;
    install_service)
        log "===== Installing Systemd Service ====="
        install_systemd_service
        ;;
    uninstall_service)
        log "===== Uninstalling Systemd Service ====="
        uninstall_systemd_service
        ;;
    start)
        if [ "$SIMULATE" = true ]; then
            log "===== SIMULATION MODE ====="
            log "[Simulate] Would backup system state"
            log "[Simulate] Would flush iptables"
            log "[Simulate] Would disable IPv6"
            log "[Simulate] Would enable IP forwarding"
            log "[Simulate] Would configure ${LAN_IF} with IP ${LAN_IP}"
            if [ "$WIFI_ENABLED" = "true" ]; then
                log "[Simulate] Would configure WiFi hotspot on ${WIFI_IF}"
                log "[Simulate]   SSID: ${WIFI_SSID}"
                log "[Simulate]   Band: ${WIFI_BAND} ($([ "$WIFI_BAND" = "a" ] && echo "5GHz" || echo "2.4GHz"))"
            else
                log "[Simulate] WiFi hotspot disabled"
            fi
            log "[Simulate] Would configure NAT on ${WAN_IF}"
            log "[Simulate] Would configure DNS routing"
            log "[Simulate] Would start dnsmasq DHCP server"
            log "[Simulate] No actual changes made"
        else
            if ! check_prerequisites; then
                log "Prerequisites not satisfied. Run with --install first."
                exit 1
            fi
            start_mitm
        fi
        ;;
    stop)
        if [ "$SIMULATE" = true ]; then
            log "===== SIMULATION MODE ====="
            log "[Simulate] Would stop hostapd"
            log "[Simulate] Would stop dnsmasq"
            log "[Simulate] Would restore iptables rules"
            log "[Simulate] Would restore IP forwarding state"
            log "[Simulate] Would restore IPv6 settings"
            log "[Simulate] Would flush ${LAN_IF} configuration"
            if [ "$WIFI_ENABLED" = "true" ]; then
                log "[Simulate] Would flush ${WIFI_IF} configuration"
            fi
            log "[Simulate] No actual changes made"
        else
            restore_system_state
        fi
        ;;
    stats)
        show_traffic_stats
        ;;
    *)
        echo "No action specified. Use --help for usage information"
        exit 1
        ;;
esac

log "===== Script execution completed ====="

exit 0
