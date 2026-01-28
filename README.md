# MITM SOURCESVR Traffic Capture Script — Complete Kali Guide

Author: Bruno DELNOZ  
Email: bruno.delnoz@protonmail.com  
Script: `mitm-clientmitm-capture.sh`  
Version: v3.0 (2025-01-28)

This document is a comprehensive, in-depth README intended to fully document, explain, and operationalize the `mitm-clientmitm-capture.sh` script on Kali Linux. It includes background, complete step-by-step instructions, internals (iptables, hostapd, dnsmasq), examples, debugging tips, helper scripts, automation patterns, security/legal guidance, and a detailed checklist.

IMPORTANT SAFETY & LEGAL NOTICE
- This script modifies system networking (IP addresses, iptables), runs `hostapd` and `dnsmasq`, and disables IPv6 while active. These are disruptive actions.
- Use only on systems/networks you own or where you have explicit authorization to perform this testing.
- Captured network traffic can contain sensitive personal data — handle and store PCAPs securely and delete them when no longer needed.
- The script does NOT perform TLS interception; decrypting TLS requires separate tooling and legal consent.

Table of Contents
1. Goals & Use Cases
2. Quick summary of script features (v3 highlights)
3. Kali-specific prerequisites and installation
4. NetworkManager, iptables/nftables, and kernel/driver notes
5. Pre-run checks and environment validation
6. Full walkthrough: start, capture, stop
7. Detailed internals and generated configs
   - iptables rules (what is added and why)
   - hostapd configuration (explain each setting)
   - dnsmasq configuration (explain each setting)
   - system state backup contents
8. Capture & analysis workflows
   - Wireshark, tshark, tcpdump examples
   - Filtering recipes for Kodi/Stalker artifacts
   - Post-processing with Zeek/tshark/scripts
9. Troubleshooting (categorized by failure mode)
10. Advanced options & automation
    - Systemd unit
    - Helper scripts (AP detection, monitor-mode)
    - CI/testing suggestions
11. Forensics, logging, and artifact retention guidance
12. Security, ethics, and legal guidance
13. Recommended hardware
14. Full changelog summary
15. Quick reference cheat sheet (commands)
16. FAQ
17. Contact & license

---

1) Goals & Use Cases

Primary goal
- Temporarily turn a Kali Linux host into a controlled MITM router for a target device called "SOURCESVR", enabling packet capture and analysis to reproduce MITMCLIENT configuration and troubleshoot.

Common use cases
- Reverse engineering device authentication and playlist retrieval.
- Capturing HTTP endpoints and parameters used by MITMCLIENT boxes.
- Testing how a device behaves when DNS is coerced to particular resolvers.
- Teaching/practice labs for network forensics and packet analysis.

Non-goals
- This script does not intercept or decrypt TLS by default.
- It does not act as a persistent router for production networks.

---

2) Quick summary of script features (v3 highlights)

- Separate subnets for Ethernet and WiFi:
  - Ethernet (eth1): 192.168.50.1/24, DHCP .10-.50
  - WiFi (wlan1): 192.168.51.1/24, DHCP .10-.50
- WiFi hotspot support via hostapd (802.11n/ac options included).
- DHCP via dnsmasq (DHCP only; DNS via iptables DNAT to WAN DNS).
- Transparent DNS routing (iptables DNAT) so client DNS requests go to WAN DNS.
- Full system-state backup (iptables, sysctl, interfaces, resolv.conf).
- Safe restore mechanism with fallback manual restore.
- Simulation/dry-run mode and automatic .gitignore management.
- Kali-specific guidance and helper patterns included.

---

3) Kali-specific prerequisites and installation

Install required packages (Debian/Kali):

sudo apt-get update  
sudo apt-get install -y iproute2 iptables procps dnsmasq hostapd iw wireless-tools net-tools rfkill tshark aircrack-ng

Notes:
- `tshark` provides CLI capture/processing.
- `aircrack-ng` includes `airmon-ng` for monitor-mode helper scripts.
- On modern Kali, `iptables` may be a wrapper for nftables. See section 4.

Optional useful packages:
- zeek (for advanced PCAP analysis)
- scapy (for scripted packet parsing)
- tcpdump (alternative to tshark)
- vim/less (for inspecting logs)

Kernel/driver considerations
- Ensure WiFi adapter drivers support AP mode (nl80211). Intel and many Atheros chipsets are good choices.
- Realtek adapters often need out-of-tree DKMS drivers; research for your chipset before relying on them.

---

4) NetworkManager, iptables/nftables, and kernel/driver notes

NetworkManager
- Kali runs NetworkManager which may reconfigure interfaces. The script uses `nmcli dev set <if> managed no` to avoid conflicts.
- Two approaches:
  - Stop NetworkManager during the test:
    sudo systemctl stop NetworkManager
  - Make specific interfaces unmanaged by editing /etc/NetworkManager/NetworkManager.conf and adding them to `unmanaged-devices` under `[keyfile]`.

iptables vs nftables
- Kali may use nftables as the default backend. The script uses legacy iptables commands and `iptables-save`/`iptables-restore`. For consistent behavior, you can choose legacy iptables:

sudo update-alternatives --config iptables
# choose /usr/sbin/iptables-legacy if needed

- If you cannot switch, the script will generally work with iptables wrappers. However, restoring saved rules may fail if backend mismatch exists. The script includes a fallback to flush rules and set ACCEPT policies.

Wireless drivers and regulatory domain
- Verify AP support:

sudo iw list | grep -A10 "Supported interface modes"

- Set regulatory domain to permit your desired channels:

sudo iw reg set BE
sudo iw reg get

- Ensure the radio is unblocked:

sudo rfkill unblock all
sudo rfkill list

---

5) Pre-run checks and environment validation

Run the script's non-invasive prerequisite check:

sudo ./mitm-clientmitm-capture.sh --prerequis

Manual pre-checks to validate environment:

# Check interfaces
ip addr show

# Check WiFi AP capability
sudo iw list | grep -A10 "Supported interface modes"

# Check that WAN_IF (internet) has connectivity
ip route get 8.8.8.8
ping -c 3 8.8.8.8

# Check hostapd & dnsmasq presence
command -v hostapd dnsmasq iptables ip sysctl

# Ensure root
[ "$EUID" -eq 0 ] || echo "Run as root or sudo"

Choose interfaces
- WAN_IF: interface connected to internet (example: wlan0 or eth0)
- LAN_IF: interface to connect the SOURCESVR device via Ethernet (example: eth1)
- WIFI_IF: interface to host the AP (example: wlan1 — must be AP-capable)

---

6) Full walkthrough: start, capture, stop

A. Preparation
1. (Optional) Snapshot your Kali VM (recommended).
2. Stop NetworkManager if you prefer:

sudo systemctl stop NetworkManager

3. Make script executable:

sudo chmod +x mitm-clientmitm-capture.sh

B. Dry-run verification
- Simulate what the script will do (no changes):

sudo ./mitm-clientmitm-capture.sh --exec --simulate

Review the simulation output for any surprises.

C. Start MITM
- Execute (default: WiFi hotspot enabled):

sudo ./mitm-clientmitm-capture.sh --exec

- If you want Ethernet-only:

sudo ./mitm-clientmitm-capture.sh --exec --wifi-disable

- To customize values (example):

sudo ./mitm-clientmitm-capture.sh --exec --lan-if enp0s8 --wan-if wlan0 --wifi-ssid "MITM_Test" --wifi-pass "ChangeMe123"

What the script does on start (concise):
- Backup system state into results/ archive.
- Flush iptables and set safe policies.
- Disable IPv6 and enable IPv4 forwarding.
- Assign LAN_IP to LAN_IF and WIFI_IP to WIFI_IF.
- Start hostapd (if enabled).
- Detect WAN DNS servers and set up iptables DNAT for port 53.
- Write dnsmasq config and start dnsmasq for DHCP.
- Add NAT MASQUERADE and FORWARD rules.

D. Connect target and capture
- Connect SOURCESVR device via Ethernet to LAN_IF or via WiFi to the SSID.
- Start Wireshark (GUI) or tshark/tcpdump to capture:
  - Wireshark (GUI):
    sudo wireshark -i eth1 -k
  - tshark (save to rotating files):
    sudo tshark -i eth1 -b filesize:10240 -w ./results/sourcesvr_capture.pcap

Recommended capture filters / display filters (Wireshark):
- Show only target device traffic:
  ip.addr == <SOURCESVR_IP>
- Show HTTP requests/responses:
  ip.addr == <SOURCESVR_IP> && http
- Show DNS:
  dns

E. Stop and restore
- When done, stop MITM and restore:

sudo ./mitm-clientmitm-capture.sh --stop

Script restore behavior:
- Reads saved state file in /tmp and attempts to restore iptables via iptables-restore from the backup.
- Restores sysctl values for ip_forward and IPv6 disabling flags.
- Stops hostapd/dnsmasq and removes config/pid files.
- Cleans up temporary files.

If restore fails, the script runs manual restore fallback (stops services, flushes iptables, sets ACCEPT policies, re-enables IPv6).

If NetworkManager was stopped earlier, restart it:

sudo systemctl start NetworkManager

---

7) Detailed internals and generated configs

A. iptables rules — what the script adds and why

1) NAT (MASQUERADE) so clients behind the MITM have internet:

iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

2) Forwarding allow client -> WAN and allow established responses:

iptables -A FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT
iptables -A FORWARD -i $WAN_IF -o $LAN_IF -m state --state ESTABLISHED,RELATED -j ACCEPT

If WiFi is enabled:

iptables -A FORWARD -i $WIFI_IF -o $WAN_IF -j ACCEPT
iptables -A FORWARD -i $WAN_IF -o $WIFI_IF -m state --state ESTABLISHED,RELATED -j ACCEPT

3) Transparent DNS (DNAT PREROUTING) so client DNS requests are directed to the system's WAN DNS:

iptables -t nat -A PREROUTING -i $LAN_IF -p udp --dport 53 -j DNAT --to-destination $wan_dns_primary:53
iptables -t nat -A PREROUTING -i $LAN_IF -p tcp --dport 53 -j DNAT --to-destination $wan_dns_primary:53

Repeat for $WIFI_IF if WiFi enabled.

4) Accept forwarding for DNS:

iptables -A FORWARD -i $LAN_IF -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -i $LAN_IF -p tcp --dport 53 -j ACCEPT

Why DNAT instead of letting clients use their DNS?
- Keeps DNS resolution deterministic and avoids clients using public DOH or other resolvers that complicate analysis.
- This script purposefully routes DNS to WAN DNS, not intercepting responses — only routing.

B. hostapd configuration template (generated to /tmp/hostapd-mitm-<timestamp>.conf)

Example contents (the script writes similar lines):

interface=wlan1
driver=nl80211
ssid=WLAN_MITM
hw_mode=a            # 'a' = 5GHz, 'g' = 2.4GHz
channel=36
country_code=BE
ieee80211n=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][DSSS_CCK-40]
ieee80211ac=1        # only if band a
vht_capab=[MAX-MPDU-11454][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1]
vht_oper_chwidth=1
vht_oper_centr_freq_seg0_idx=42
wmm_enabled=1
ieee80211d=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=SECUREPASS
macaddr_acl=0
ignore_broadcast_ssid=0

Key explanations
- driver=nl80211: modern mac80211 stack driver interface.
- ht_capab / vht_capab: tune throughput features (HT40, VHT80).
- vht_oper_chwidth and central freq: VHT channel width settings used on 5GHz.
- wpa_passphrase: WPA2-PSK passphrase (min 8 chars).

C. dnsmasq configuration template (generated to /tmp/dnsmasq-sourcesvr-<timestamp>.conf)

Example contents:

# dnsmasq configuration for MITM capture (DHCP only, DNS disabled)
interface=eth1
interface=wlan1
bind-interfaces

# DHCP for Ethernet (eth1)
dhcp-range=interface:eth1,192.168.50.10,192.168.50.50,12h
dhcp-option=interface:eth1,3,192.168.50.1
dhcp-option=interface:eth1,6,192.168.50.1

# DHCP for WiFi (wlan1)
dhcp-range=interface:wlan1,192.168.51.10,192.168.51.50,12h
dhcp-option=interface:wlan1,3,192.168.51.1
dhcp-option=interface:wlan1,6,192.168.51.1

port=0         # disables DNS listening (dnsmasq acts only as DHCP server)
log-dhcp

Key explanations
- dhcp-option 3: router/gateway IP
- dhcp-option 6: DNS server IP provided to client (script sets gateway IP so clients point to the MITM gateway)
- port=0: disables dnsmasq DNS service to avoid conflicting with iptables DNAT behavior (script handles DNS routing via iptables)

D. System state backup contents (archive `results/system-state-backup.<timestamp>.tar.gz`)

Typical saved files:
- ip_forward.txt (sysctl net.ipv4.ip_forward)
- ipv6_all.txt, ipv6_default.txt (IPv6 disable flags)
- iptables.rules (iptables-save output)
- iptables_nat.rules (iptables -t nat -S)
- interfaces.txt (ip addr show)
- routes.txt (ip route show)
- lan_config.txt and wifi_config.txt (per-interface ip addr show)
- resolv.conf (copy of /etc/resolv.conf)

These files are used by restore_system_state() to attempt an accurate restoration.

---

8) Capture & analysis workflows

A. Recommended capture targets
- Capture on the wired LAN interface (LAN_IF — e.g., eth1) for completeness and stability.
- If capturing WiFi 802.11 management frames is required, use a separate monitor-mode adapter (do not use the AP interface for full 802.11 headers capture).

B. wireshark / tshark / tcpdump examples

Start Wireshark GUI on LAN interface:
sudo wireshark -i eth1 -k

tshark to file with size-rotation:
sudo tshark -i eth1 -b filesize:10240 -w ./results/capture-%Y%m%d_%H%M%S.pcap

tcpdump to file (rotate by size):
sudo tcpdump -i eth1 -w ./results/capture.pcap -C 100

Extract HTTP URIs from pcap:
tshark -r capture.pcap -Y http.request -T fields -e http.host -e http.request.uri

Extract DNS queries and responses:
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e dns.resp.addr

C. Filters to find Kodi / Stalker artifacts
- Look for typical keywords in URIs or payloads:
  - /stalker_portal, /player_api.php, get_profile, m3u
- Wireshark display filter examples:
  - ip.addr == <SOURCESVR_IP> && http.request.uri contains "player_api"
  - http and (http.request.uri contains "m3u" or http.request.uri contains "playlist")
  - dns.qry.name contains "stalker" or dns.qry.name contains "mag"

D. Post-processing automation examples
Use Zeek to produce extracted HTTP logs:

zeek -r capture.pcap

Then inspect `http.log`, `dns.log`, etc.

Use tshark to extract JSON or CSV lines for automation:
tshark -r capture.pcap -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.uri

---

9) Troubleshooting (categorized by failure mode)

A. hostapd issues
Symptoms: hostapd fails to start, immediate exit, or crashes.
Checks & fixes:
- Verify AP support: `iw list` -> check for AP mode in "Supported interface modes".
- Confirm interface has IP assigned prior to hostapd start (script assigns WIFI_IP before starting hostapd).
- Inspect logs:
  tail -n 200 ./logs/log.<scriptname>.<timestamp>.v3.0.log
  journalctl -u hostapd -n 200
  dmesg | tail -n 200
- Try lowering advanced VHT options (script toggles them only when band=a). Use 2.4GHz if 5GHz unsupported.

B. dnsmasq errors (won't start / cannot bind)
Symptoms: dnsmasq error binding to interface, no DHCP leases observed.
Checks:
- Ensure the interface has the configured IP.
- Check that `port=0` is in the dnsmasq config if DNS is being handled elsewhere (script sets this intentionally).
- Inspect `/var/log/syslog` or script log for dnsmasq error messages.
- Ensure there is no other DHCP server active on the same subnet (router or another host).

C. iptables restore fails on --stop
Symptoms: script cannot restore saved iptables rules.
Checks:
- iptables backend mismatch: determine if iptables-legacy vs iptables-nft are installed.
  sudo update-alternatives --config iptables
- If restore fails, the script will flush and reset to ACCEPT to prevent network lockout. You may need to reboot to return to your distro's expected iptables/nftables state.

D. No internet for client
Checks:
- Verify MASQUERADE rule exists:
  sudo iptables -t nat -S | grep MASQUERADE
- Verify forwarding rules exist and `sysctl net.ipv4.ip_forward` is 1.
- Verify WAN_IF connectivity:
  ip route get 8.8.8.8
  ping -c 3 8.8.8.8

E. NetworkManager reclaims interfaces / resets IPs
Fix:
- Mark interfaces unmanaged in `/etc/NetworkManager/NetworkManager.conf` under `[keyfile]` with `unmanaged-devices` or stop NetworkManager during testing.

F. WiFi adapter rfkill or driver issues
Fix:
- `sudo rfkill unblock all`
- Inspect `dmesg` for driver messages. Consider switching adapters if driver is unstable.

---

10) Advanced options & automation

A. Systemd unit (lab-only)
Create `/etc/systemd/system/mitm-sourcesvr.service`:

[Unit]
Description=MITM SOURCESVR capture mode (lab only)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/mitm-clientmitm-capture.sh --exec
ExecStop=/usr/local/bin/mitm-clientmitm-capture.sh --stop
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target

Enable & start:
sudo cp mitm-clientmitm-capture.sh /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable --now mitm-sourcesvr.service

B. Helper: detect AP-capable interface script (Kali)

Save as `detect_ap.sh` and run as root:

#!/bin/bash
echo "Detecting AP-capable PHYs (requires iw):"
for phy in /sys/class/ieee80211/*; do
  name=$(basename "$phy")
  if iw phy "$name" info 2>/dev/null | grep -q "AP"; then
    echo "PHY $name supports AP mode"
    # map phy to interface names
    for dev in /sys/class/ieee80211/$name/device/net/*; do
      echo "  Interface: $(basename "$dev")"
    done
  fi
done

C. Automated capture rotation example (tshark ring buffer)

sudo tshark -i eth1 -b filesize:10240 -b files:10 -w ./results/capture.pcap

This produces up to 10 files each rotated at 10MB.

D. Test automation
- Use a VM with multiple virtual interfaces (veth pairs) to test the script safely.
- Create unit tests for parsing functions or config templating using bats or simple shell tests.

---

11) Forensics, logging, and artifact retention guidance

Artifacts created by script:
- `./logs/log.<script>.<timestamp>.v3.0.log` — operational log
- `./results/system-state-backup.<timestamp>.tar.gz` — backup archive
- `./results/*.pcap` — captures produced by you
- `/tmp/dnsmasq-sourcesvr-<timestamp>.conf` — temporary generated config
- `/tmp/hostapd-mitm-<timestamp>.conf` — temporary generated config

Retention policy recommendations
- Keep backups long enough to verify restore, then move to secure long-term storage if needed.
- PCAPs can contain sensitive data. Apply retention schedule (e.g., 30 days) and store PCAPs encrypted if they must be kept longer.

Logrotate & disk monitoring
- Use logrotate for `./logs` and set a quota for `./results` to avoid disk exhaustion.
- Monitor disk space and use rotated tshark/tcpdump to limit single-file sizes.

Access control
- Restrict access to logs and PCAPs (chmod 600) and store on encrypted partitions when possible.

---

12) Security, ethics, and legal guidance

- Obtain explicit permission before capturing or modifying network traffic on networks/devices you do not own.
- Do not use the script to intercept communications of others without consent — doing so may be illegal.
- Do not attempt to break HTTPS encryption without explicit authorization — TLS interception is beyond the scope of this script and carries significant legal/ethical burden.
- Keep copies of consent/authorization documentation when performing testing for clients.

---

13) Recommended hardware

For reliable AP and capture work, recommended WiFi adapters:
- Intel (internal cards): Intel AC 7260, 8265, AX200 — reliable with mainline drivers.
- Atheros (USB): AR9271, AR9280 series (good AP & monitor support).
- USB adapters with chipsets supported by mac80211 (avoid unmaintained Realtek drivers unless you have tested drivers).

Use a second USB WiFi adapter dedicated for monitor-mode capture if you need raw 802.11 headers.

---

14) Full changelog summary (short)

See script `--changelog` for full details. High-level highlights:
- v3.0 — Separate Ethernet/WiFi subnets, ensure WiFi IP before dnsmasq, hostapd VHT/HT tuning, robust cleanup.
- v2.5 — Added WiFi hotspot via hostapd, unified DHCP + hostapd integration.
- v1.x — initial MITM DHCP/DNS/NAT functionality and iterative improvements.

---

15) Quick reference cheat sheet (commands)

Make executable:
chmod +x mitm-clientmitm-capture.sh

Check prerequisites:
sudo ./mitm-clientmitm-capture.sh --prerequis

Install prerequisites:
sudo ./mitm-clientmitm-capture.sh --install

Dry-run:
sudo ./mitm-clientmitm-capture.sh --exec --simulate

Start MITM:
sudo ./mitm-clientmitm-capture.sh --exec

Start MITM without WiFi:
sudo ./mitm-clientmitm-capture.sh --exec --wifi-disable

Stop & restore:
sudo ./mitm-clientmitm-capture.sh --stop

Show help:
./mitm-clientmitm-capture.sh --help

Check AP capability:
sudo iw list | grep -A10 "Supported interface modes"

View dnsmasq leases:
sudo cat /var/lib/misc/dnsmasq.leases

Show iptables NAT rules:
sudo iptables -t nat -S

---

16) FAQ

Q: Can I inspect HTTPS traffic with this script?
A: No. The script routes traffic and captures packets, but HTTPS payloads are encrypted. TLS MITM requires a proxy and installing a CA on the client — do not do this without explicit authorization.

Q: Why is dnsmasq started with port=0 (DNS disabled)?
A: The script intentionally uses dnsmasq for DHCP only, and relies on iptables DNAT to direct DNS requests to the WAN DNS. This avoids dnsmasq acting as a DNS resolver and makes DNS routing deterministic.

Q: What if NetworkManager keeps reconfiguring interfaces?
A: Mark interfaces unmanaged in NetworkManager config (or stop NetworkManager during the MITM session).

Q: The script created /tmp files — are they removed?
A: Yes — cleanup_temp_files() removes the temporary config and pid files on `--stop`. The backup archive remains in ./results for restore verification.

---

17) Contact & license

Author: Bruno DELNOZ  
Email: bruno.delnoz@protonmail.com

License: The original script header did not include a license. Treat the code as "use at your own risk" until the author provides an explicit license. Contact the author to discuss redistribution or contributions.

---

Appendix A — Example troubleshooting commands

# View script log (recent)
less ./logs/log.mitm-clientmitm-capture.sh.<timestamp>.v3.0.log

# Show NAT rules and PREROUTING DNAT
sudo iptables -t nat -S

# Show filter rules
sudo iptables -S

# Check net.ipv4.ip_forward
sysctl net.ipv4.ip_forward

# Check IPv6 disable flags
sysctl net.ipv6.conf.all.disable_ipv6
sysctl net.ipv6.conf.default.disable_ipv6

# Inspect dnsmasq config created by script
cat /tmp/dnsmasq-sourcesvr-<timestamp>.conf

# Inspect hostapd config created by script
cat /tmp/hostapd-mitm-<timestamp>.conf

---

Appendix B — Example hostapd and dnsmasq minimal files (for manual testing)

Example hostapd.conf (manual):
interface=wlan1
driver=nl80211
ssid=MITM_TEST
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=ChangeMe123

Start hostapd manually:
sudo hostapd -dd /path/to/hostapd.conf

Example dnsmasq.conf (manual):
interface=wlan1
bind-interfaces
dhcp-range=192.168.51.10,192.168.51.50,12h
dhcp-option=3,192.168.51.1
dhcp-option=6,192.168.51.1
port=0
log-dhcp

Start dnsmasq manually:
sudo dnsmasq --conf-file=/path/to/dnsmasq.conf --pid-file=/tmp/dnsmasq.man.pid

