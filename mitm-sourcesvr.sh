#!/bin/bash
################################################################################
# Author: Bruno DELNOZ
# Email: bruno.delnoz@protonmail.com
# Script name with full path: /root/mitm-clientmitm-capture.sh
# Target usage: MITM router setup for SOURCESVR traffic capture and analysis
# Version: v3 – Date: 2025-01-28
#
# TODO
# - chage clientmitm  clientmitm
# - adapt iptables sections to be more restricive
# - adapt rea   dme to set export MITM_AP_PASSWORD= in .bashrc
#
#
# Changelog:
# v3.0 - 2025-01-28 - MAJOR RELEASE: Separate Subnets & Performance Optimization
# Fixed critical dnsmasq startup issue (wlan1 needs IP before dnsmasq starts)
# Separated Ethernet and WiFi on different subnets to avoid IP conflicts
# - Ethernet (eth1): 192.168.50.0/24 (DHCP: .10-.50)
# - WiFi (wlan1): 192.168.51.0/24 (DHCP: .10-.50)
# Added new WiFi-specific configuration variables (WIFI_IP, WIFI_DHCP_START/END)
# Optimized WiFi performance with 802.11n/ac enhancements
# - HT40 (40MHz channel width) for 2.4GHz: ~300 Mbps
# - VHT80 (80MHz channel width) for 5GHz: ~867 Mbps
# - Enabled SHORT-GI (Short Guard Interval) for better throughput
# Enhanced hostapd configuration with advanced capabilities
# Added cleanup_temp_files() function for proper temporary file management
# Fixed temporary files not being removed on --stop
# Improved restore_system_state() with automatic cleanup
# Added --start alias for --exec command
# Both Ethernet and WiFi devices now work independently
# Complete error handling for WiFi hotspot failures with automatic fallback
# v2.5 - 2025-01-27 - MAJOR RELEASE: Complete WiFi Hotspot Integration
# v2.1 - 2025-01-27 - Minor corrections to dnsmasq & dhcp configuration
# v1.7-v1.0 - Earlier versions (see --changelog for full history)
################################################################################
set -e

################################################################################
# DEFAULT CONFIGURATION VARIABLES
################################################################################
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

# WiFi Hotspot Configuration
WIFI_ENABLED="true"                  # WiFi hotspot ENABLED by default
WIFI_IP="192.168.51.1"               # IP address for WiFi gateway
WIFI_NETMASK="24"                    # Netmask for WiFi network
WIFI_DHCP_START="192.168.51.10"      # DHCP pool start for WiFi
WIFI_DHCP_END="192.168.51.50"        # DHCP pool end for WiFi
WIFI_ENABLED="true"                  # WiFi hotspot ENABLED by default
WIFI_SSID="WLAN_MITM"                # SSID of the WiFi hotspot
WIFI_PASSWORD="$MITM_AP_PASSWORD"      # WPA2 password (min 8 chars)
WIFI_BAND="a"                        # WiFi band: a=5GHz, g=2.4GHz
WIFI_CHANNEL="36"                    # WiFi channel (5GHz: 36,40,44,48 / 2.4GHz: 1-13)
WIFI_COUNTRY="BE"                    # Country code (Belgium)


################################################################################
# PATHS AND FILES
################################################################################
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VERSION="v3.0"

# Create required directories
LOGS_DIR="${SCRIPT_DIR}/logs"
RESULTS_DIR="${SCRIPT_DIR}/results"
INFOS_DIR="${SCRIPT_DIR}/infos"
mkdir -p "$LOGS_DIR" "$RESULTS_DIR" "$INFOS_DIR"

# Log file
LOGFILE="${LOGS_DIR}/log.${SCRIPT_NAME}.${TIMESTAMP}.${VERSION}.log"

# State backup file
STATE_BACKUP="${RESULTS_DIR}/system-state-backup.${TIMESTAMP}.tar.gz"

# Temporary files
DNSMASQ_CONF="/tmp/dnsmasq-sourcesvr-${TIMESTAMP}.conf"
DNSMASQ_PID="/tmp/dnsmasq-sourcesvr-${TIMESTAMP}.pid"
HOSTAPD_CONF="/tmp/hostapd-mitm-${TIMESTAMP}.conf"
HOSTAPD_PID="/tmp/hostapd-mitm-${TIMESTAMP}.pid"
STATE_FILE="/tmp/mitm-state-${TIMESTAMP}.txt"

################################################################################
# LOGGING FUNCTION
################################################################################
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" | tee -a "$LOGFILE"
}

################################################################################
# GITIGNORE MANAGEMENT
################################################################################
manage_gitignore() {
    log "[GitIgnore] Managing .gitignore file"
    local gitignore_file="${SCRIPT_DIR}/.gitignore"
    local entries_to_add=("/logs" "/results" "/outputs" "/infos")
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
# BACKUP CURRENT SYSTEM STATE
################################################################################
backup_system_state() {
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
# hostapd configuration for MITM WiFi hotspot
interface=${WIFI_IF}
driver=nl80211
ssid=${WIFI_SSID}
hw_mode=${WIFI_BAND}
channel=${WIFI_CHANNEL}
country_code=${WIFI_COUNTRY}
# txpower=30
# 802.11n settings (HT - High Throughput)
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][DSSS_CCK-40]
# 802.11ac settings (VHT - Very High Throughput) for 5GHz
ieee80211ac=$([ "$WIFI_BAND" = "a" ] && echo "1" || echo "0")
$([ "$WIFI_BAND" = "a" ] && echo "vht_capab=[MAX-MPDU-11454][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1]")
$([ "$WIFI_BAND" = "a" ] && echo "vht_oper_chwidth=1")
$([ "$WIFI_BAND" = "a" ] && echo "vht_oper_centr_freq_seg0_idx=42")
# WMM (Wi-Fi Multimedia) for QoS
wmm_enabled=1
# 802.11d (country regulatory)
ieee80211d=1
# WPA2-PSK Configuration
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=${WIFI_PASSWORD}
# Additional settings
macaddr_acl=0
ignore_broadcast_ssid=0
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
# START MITM CONFIGURATION
################################################################################
start_mitm() {
    log "[MITM] ===== Starting MITM Configuration ====="

    # Backup current state first
    backup_system_state

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
    log "[MITM] (2/12) Disabling IPv6 to prevent leaks"
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null
    log "[MITM] IPv6 disabled"

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
            log "[MITM] Warning: WiFi hotspot configuration failed, continuing with Ethernet only"
            WIFI_ENABLED="false"
            ip addr flush dev "$WIFI_IF" 2>/dev/null || true
            ip link set "$WIFI_IF" down 2>/dev/null || true
        fi
    else
        log "[MITM] (5/12) WiFi hotspot disabled, skipping"
    fi


    # Step 6: Get WAN DNS servers
    log "[MITM] (6/12) Detecting DNS servers from system"
    local wan_dns_primary=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -n 1)
    local wan_dns_secondary=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | sed -n '2p')

    if [ -z "$wan_dns_primary" ]; then
        wan_dns_primary="8.8.8.8"
        wan_dns_secondary="8.8.4.4"
        log "[MITM] Warning: No DNS found, using Google DNS: $wan_dns_primary, $wan_dns_secondary"
    else
        log "[MITM] Using DNS servers: Primary=$wan_dns_primary, Secondary=$wan_dns_secondary"
    fi

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

    # Step 8: Configure DNS routing (DNAT for DNS requests to WAN DNS)
    log "[MITM] (8/12) Configuring DNS routing to WAN DNS servers"

    # Redirect DNS queries from LAN
    iptables -t nat -A PREROUTING -i "$LAN_IF" -p udp --dport 53 -j DNAT --to-destination "$wan_dns_primary:53"
    iptables -t nat -A PREROUTING -i "$LAN_IF" -p tcp --dport 53 -j DNAT --to-destination "$wan_dns_primary:53"
    iptables -A FORWARD -i "$LAN_IF" -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -i "$LAN_IF" -p tcp --dport 53 -j ACCEPT

    # Redirect DNS queries from WiFi (if WiFi enabled)
    if [ "$WIFI_ENABLED" = "true" ]; then
        iptables -t nat -A PREROUTING -i "$WIFI_IF" -p udp --dport 53 -j DNAT --to-destination "$wan_dns_primary:53"
        iptables -t nat -A PREROUTING -i "$WIFI_IF" -p tcp --dport 53 -j DNAT --to-destination "$wan_dns_primary:53"
        iptables -A FORWARD -i "$WIFI_IF" -p udp --dport 53 -j ACCEPT
        iptables -A FORWARD -i "$WIFI_IF" -p tcp --dport 53 -j ACCEPT
    fi

    log "[MITM] DNS requests from LAN/WiFi will be routed to ${wan_dns_primary}"

    # Step 9: Create dnsmasq configuration for DHCP
    log "[MITM] (9/12) Creating dnsmasq DHCP configuration"

    # Build interface list for dnsmasq
    local dnsmasq_interfaces="interface=${LAN_IF}"
    if [ "$WIFI_ENABLED" = "true" ]; then
        dnsmasq_interfaces="${dnsmasq_interfaces}
interface=${WIFI_IF}"
    fi

cat > "$DNSMASQ_CONF" <<EOF
# dnsmasq configuration for MITM capture (DHCP only, DNS disabled)
interface=${LAN_IF}
interface=${WIFI_IF}
bind-interfaces

# DHCP for Ethernet (eth1)
dhcp-range=interface:${LAN_IF},${DHCP_RANGE_START},${DHCP_RANGE_END},${DHCP_LEASE_TIME}
dhcp-option=interface:${LAN_IF},3,${LAN_IP}
dhcp-option=interface:${LAN_IF},6,${DNS1_IP},${DNS2_IP}

# DHCP for WiFi (wlan1)
dhcp-range=interface:${WIFI_IF},${WIFI_DHCP_START},${WIFI_DHCP_END},${DHCP_LEASE_TIME}
dhcp-option=interface:${WIFI_IF},3,${WIFI_IP}
dhcp-option=interface:${WIFI_IF},6,${DNS1_IP},${DNS2_IP}

port=53
log-dhcp
EOF

    log "[MITM] dnsmasq configuration created (DHCP on eth1${WIFI_ENABLED:+ and wlan1})"

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
        log "[MITM]   Password: ${WIFI_PASSWORD}"
        log "[MITM]   Band: ${WIFI_BAND} ($([ "$WIFI_BAND" = "a" ] && echo "5GHz" || echo "2.4GHz"))"
        log "[MITM]   Channel: ${WIFI_CHANNEL}"
        log "[MITM]   Country: ${WIFI_COUNTRY}"
        log "[MITM]   Security: WPA2-PSK (CCMP/AES)"
    else
        log "[MITM] WiFi Hotspot: Disabled"
    fi

    log "[MITM] "
    log "[MITM] WAN Interface: ${WAN_IF}"
    log "[MITM] DHCP Range: ${DHCP_RANGE_START} - ${DHCP_RANGE_END}"
    log "[MITM] DHCP Lease Time: ${DHCP_LEASE_TIME}"
    log "[MITM] DNS Routing: Transparent to ${wan_dns_primary} (via iptables DNAT)"
    log "[MITM] "
    log "[MITM] Next steps:"
    log "[MITM] 1. Connect SOURCESVR device via:"
    log "[MITM]    - Ethernet: Connect to ${LAN_IF} port"

    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM]    - WiFi: Connect to SSID '${WIFI_SSID}' with password '${WIFI_PASSWORD}'"
    fi

    log "[MITM] 2. Device will receive IP via DHCP (${DHCP_RANGE_START} - ${DHCP_RANGE_END})"
    log "[MITM] 3. Start Wireshark: wireshark -i ${LAN_IF} -k"

    if [ "$WIFI_ENABLED" = "true" ]; then
        log "[MITM]    (or wireshark -i ${WIFI_IF} -k for WiFi traffic)"
    fi

    log "[MITM] 4. Apply Wireshark filter: ip.addr == <SOURCESVR_IP> && http"
    log "[MITM] "
    log "[MITM] To check DHCP leases: cat /var/lib/misc/dnsmasq.leases"
    log "[MITM] To stop and restore: $0 --stop"
    log "[MITM] ================================"
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

    # If nothing to install, exit early
    if [ ${#packages_to_install[@]} -eq 0 ]; then
        log "[Install] All prerequisites are already installed"
        log "[Install] Nothing to install"
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
    --stop, -st          Stop MITM and restore system state

OPTIONAL ARGUMENTS:
    --help, -h           Display this help message (default if no args)
    --prerequis, -pr     Check prerequisites only
    --install, -i        Install missing prerequisites
    --simulate, -s       Simulate execution (dry-run)
    --changelog, -ch     Display full changelog

NETWORK CONFIGURATION OPTIONS:
    --lan-if <if>        LAN interface name (default: ${LAN_IF})
    --wan-if <if>        WAN interface name (default: ${WAN_IF})
    --lan-ip <ip>        LAN gateway IP address (default: ${LAN_IP})
    --lan-netmask <mask> LAN netmask in CIDR (default: ${LAN_NETMASK})
    --clientmitm-range <range> DHCP IP range (default: ${DHCP_RANGE_START}-${DHCP_RANGE_END})

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
    DHCP Range: ${DHCP_RANGE_START} - ${DHCP_RANGE_END}

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

    # Start MITM with default settings (Ethernet + WiFi hotspot)
    sudo ./${SCRIPT_NAME} --exec

    # Start MITM with Ethernet only (WiFi disabled)
    sudo ./${SCRIPT_NAME} --exec --wifi-disable

    # Start MITM with custom WiFi SSID and password
    sudo ./${SCRIPT_NAME} --exec --wifi-ssid "MyMITM" --wifi-pass "MySecurePass123"

    # Start MITM with 2.4GHz WiFi instead of 5GHz
    sudo ./${SCRIPT_NAME} --exec --wifi-band g --wifi-channel 6

    # Start MITM with custom LAN configuration
    sudo ./${SCRIPT_NAME} --exec --lan-ip 10.0.0.1 --clientmitm-range 10.0.0.10-10.0.0.50

    # Simulate execution without changes
    sudo ./${SCRIPT_NAME} --simulate --exec

    # Stop MITM and restore system
    sudo ./${SCRIPT_NAME} --stop

WIRESHARK CAPTURE COMMANDS:
    # Capture Ethernet traffic
    wireshark -i ${LAN_IF} -k

    # Capture WiFi hotspot traffic
    wireshark -i ${WIFI_IF} -k

    # Capture with pre-filter
    wireshark -i ${LAN_IF} -k -f 'net ${LAN_IP%.*}.0/24'

    # Display filters (apply after capture starts):
    - All SOURCESVR traffic: ip.addr == <SOURCESVR_IP>
    - HTTP only: ip.addr == <SOURCESVR_IP> && http
    - HTTPS only: ip.addr == <SOURCESVR_IP> && tcp.port == 443
    - DNS queries: dns
    - Specific server: ip.dst == <SERVER_IP>

SOURCESVR DEVICE CONFIGURATION:
    Option 1 - Ethernet Connection:
    - Connect device to ${LAN_IF} via Ethernet cable
    - Configure for DHCP (automatic)

    Option 2 - WiFi Connection:
    - Connect to WiFi network: ${WIFI_SSID}
    - WiFi Password: ${WIFI_PASSWORD}
    - Configure for DHCP (automatic)

    The device will automatically receive:
    - IP Address: ${DHCP_RANGE_START} - ${DHCP_RANGE_END}
    - Gateway: ${LAN_IP}
    - DNS: ${LAN_IP} (routed transparently to WAN DNS)


FILES CREATED:
    Logs: ${LOGS_DIR}/log.${SCRIPT_NAME}.<timestamp>.${VERSION}.log
    Backups: ${RESULTS_DIR}/system-state-backup.<timestamp>.tar.gz

NOTES:
    - All modifications are fully reversible
    - System state is backed up before any changes
    - Use --stop to restore original configuration
    - DNS queries are forwarded to WAN DNS (not intercepted)
    - IPv6 is disabled to prevent traffic leaks
    - WiFi hotspot uses WPA2-PSK (CCMP/AES) encryption
    - Both Ethernet and WiFi share the same subnet
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
- Automatic IP assignment to wlan1 before starting hostapd/dnsmasq
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

v2.1 - 2025-01-27 - Minor corrections to dnsmasq & dhcp configuration
-----------------
- Corrected dnsmasq DHCP configuration issues
- Minor bug fixes

v1.7 - 2025-01-17
-----------------
- Re-added DHCP server functionality with dnsmasq
- SOURCESVR device now gets IP automatically via DHCP
- Added dnsmasq back to prerequisites
- DNS still routed transparently to WAN DNS via iptables
- Combined DHCP (dnsmasq) + DNS routing (iptables DNAT)

v1.6 - 2025-01-17
-----------------
- Added configurable command-line arguments for all network parameters
- New options: --lan-if, --wan-if, --lan-ip, --lan-netmask, --clientmitm-range
- All parameters now customizable via command line with sensible defaults
- Help dynamically shows current default values
- Supports custom interface names (enp0s3, wlp2s0, etc.)
- Enhanced examples showing various configuration combinations

v1.5 - 2025-01-17
-----------------
- MAJOR: Removed dnsmasq dependency completely
- Implemented DNS routing via iptables DNAT rules
- DNS requests transparently routed to WAN DNS servers
- SOURCESVR device requires STATIC IP configuration
- Reduced dependencies: only iptables, iproute2, procps needed

v1.4 - 2025-01-17
-----------------
- Optimized --install to skip apt update when all prerequisites satisfied
- Only installs actually missing packages
- Faster execution when nothing to install

v1.3 - 2025-01-17
-----------------
- Enhanced --prerequis to display installable packages
- Shows detailed list of missing packages with names
- Provides clear installation command suggestion

v1.2 - 2025-01-17
-----------------
- Fixed help display order
- Help now shows BEFORE gitignore management

v1.1 - 2025-01-17
-----------------
- Added proper argument handling with --help as default
- All mandatory arguments with short versions
- Help displayed by default when no arguments provided

v1.0 - 2025-01-17
-----------------
- Initial release
- Full MITM routing configuration
- DHCP server with dnsmasq
- DNS forwarding to WAN DNS servers
- Complete system state backup and restore
- iptables NAT configuration
- IPv6 leak prevention
- Comprehensive logging
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
        --exec|-exe)
            ACTION="start"
            shift
            ;;
        --start|-st)
            ACTION="start"
            shift
            ;;
            --stop|-st)
            ACTION="stop"
            shift
            ;;
        --simulate|-s)
            SIMULATE=true
            shift
            ;;
        --lan-if)
            LAN_IF="$2"
            shift 2
            ;;
        --wan-if)
            WAN_IF="$2"
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
        --clientmitm-range)
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
            shift 2
            ;;
        --wifi-ssid)
            WIFI_SSID="$2"
            shift 2
            ;;
        --wifi-pass)
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
    *)
        echo "No action specified. Use --help for usage information"
        exit 1
        ;;
esac

log "===== Script execution completed ====="

sleep 10
exit 0
