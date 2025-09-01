#!/usr/bin/env bash
# cis_check.sh - CIS FortiGate Firewall 7.0.x Benchmark v1.3.0 Check
# Usage: bash cis_check.sh <CONFIG_FILE> <OUTPUT_FILE>

CONFIG_FILE="$1"
OUTPUT_FILE="$2"

# Input validation
if [ -z "$CONFIG_FILE" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Error: Usage: $0 <CONFIG_FILE> <OUTPUT_FILE>" >&2
    exit 1
fi

if [ ! -r "$CONFIG_FILE" ]; then
    echo "Error: Config file '$CONFIG_FILE' does not exist or is not readable" >&2
    exit 1
fi

if ! touch "$OUTPUT_FILE" 2>/dev/null; then
    echo "Error: Cannot write to output file '$OUTPUT_FILE'" >&2
    exit 1
fi

: > "$OUTPUT_FILE" # Clear output file

report_finding() {
    local id="$1" title="$2" description="$3" risk="$4" status="$5" fix_type="$6" remediation="$7"
    echo "FINDING_ID=$id;TITLE=$title;DESCRIPTION=$description;RISK=$risk;STATUS=$status;FIX_TYPE=$fix_type;REMEDIATION=$remediation" >> "$OUTPUT_FILE"
}

# --- Network Settings ---
control_1() { # 1.1 Ensure DNS server is configured (Automated)
    local title="Ensure DNS server is configured"
    local description="Configures primary and secondary DNS servers to ensure reliable name resolution."
    if grep -A 10 "config system dns" "$CONFIG_FILE" | grep -q "set primary 8.8.8.8" 2>/dev/null && \
       grep -A 10 "config system dns" "$CONFIG_FILE" | grep -q "set secondary 8.8.4.4" 2>/dev/null; then
        report_finding "FG-1.1" "$title" "$description" "Medium" "Pass" "Planned" "DNS servers are configured (8.8.8.8, 8.8.4.4). Auditor: Verify these are appropriate for your environment."
    else
        report_finding "FG-1.1" "$title" "$description" "Medium" "Fail" "Quick" "Configure DNS servers: 'config system dns' 'set primary 8.8.8.8' 'set secondary 8.8.4.4' 'end'. Auditor: Verify DNS server addresses."
    fi
}

control_2() { # 1.2 Ensure intra-zone traffic is not always allowed (Manual)
    local title="Ensure intra-zone traffic is not always allowed"
    local description="Blocks intra-zone traffic to prevent unauthorized communication within the same zone."
    if grep -A 10 "config system zone" "$CONFIG_FILE" | grep -q "set intrazone block" 2>/dev/null; then
        report_finding "FG-1.2" "$title" "$description" "High" "Pass" "Planned" "Intra-zone traffic is blocked. Auditor: Confirm this aligns with network policy."
    else
        report_finding "FG-1.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Network > Interfaces, select zone, ensure 'Block intra-zone traffic' is enabled) or CLI ('config system zone' 'edit <zone>' 'set intrazone block' 'end'). Update verdict based on findings."
    fi
}

control_3() { # 1.3 Disable all management related services on WAN port (Manual)
    local title="Disable management services on WAN port"
    local description="Disables management services (HTTP, Telnet, SNMP, Radius) on WAN interfaces to reduce attack surface."
    if ! grep -A 10 "config system interface" "$CONFIG_FILE" | grep -q "set allowaccess.*\(http\|telnet\|snmp\|radius-acct\)" 2>/dev/null; then
        report_finding "FG-1.3" "$title" "$description" "High" "Pass" "Planned" "No management services (HTTP, Telnet, SNMP, Radius) enabled on WAN interface. Auditor: Confirm WAN interface settings."
    else
        report_finding "FG-1.3" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Network > Interfaces, select WAN, ensure HTTP, Telnet, SNMP, Radius are disabled) or CLI ('config system interface' 'edit <wan>' 'unset allowaccess http telnet snmp radius-acct' 'end'). Update verdict."
    fi
}

# --- System Settings ---
control_4() { # 2.1.1 Ensure 'Pre-Login Banner' is set (Automated)
    local title="Ensure Pre-Login Banner is set"
    local description="Enables a pre-login banner to display legal or security notices before authentication."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set pre-login-banner enable" 2>/dev/null; then
        report_finding "FG-2.1.1" "$title" "$description" "Low" "Pass" "Planned" "Pre-login banner is enabled. Auditor: Verify banner content in GUI (System > Replacement Messages > Pre-login Disclaimer Message)."
    else
        report_finding "FG-2.1.1" "$title" "$description" "Low" "Fail" "Quick" "Enable pre-login banner: 'config system global' 'set pre-login-banner enable' 'end'. Auditor: Configure and verify banner content."
    fi
}

control_5() { # 2.1.2 Ensure 'Post-Login-Banner' is set (Automated)
    local title="Ensure Post-Login Banner is set"
    local description="Enables a post-login banner to display notices after successful authentication."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set post-login-banner enable" 2>/dev/null; then
        report_finding "FG-2.1.2" "$title" "$description" "Low" "Pass" "Planned" "Post-login banner is enabled. Auditor: Verify banner content in GUI (System > Replacement Messages > Post-login Disclaimer Message)."
    else
        report_finding "FG-2.1.2" "$title" "$description" "Low" "Fail" "Quick" "Enable post-login banner: 'config system global' 'set post-login-banner enable' 'end'. Auditor: Configure and verify banner content."
    fi
}

control_6() { # 2.1.3 Ensure timezone is properly configured (Manual)
    local title="Ensure timezone is properly configured"
    local description="Sets the correct timezone to ensure accurate time-based logging and operations."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set timezone [0-9]\+" 2>/dev/null; then
        report_finding "FG-2.1.3" "$title" "$description" "Low" "Pass" "Planned" "Timezone is configured. Auditor: Verify timezone ID (e.g., 12 for Eastern Time) matches environment."
    else
        report_finding "FG-2.1.3" "$title" "$description" "Low" "Manual" "Quick" "Auditor: Check GUI (System > Settings, verify timezone) or CLI ('config system global' 'set timezone <ID>' 'end'). Use 'set timezone ?' for ID list. Update verdict."
    fi
}

control_7() { # 2.1.4 Ensure correct system time is configured through NTP (Automated)
    local title="Ensure correct system time via NTP"
    local description="Synchronizes system time with an NTP server for accurate logging and time-based functions."
    if grep -A 10 "config system ntp" "$CONFIG_FILE" | grep -q "set ntpsync enable" 2>/dev/null; then
        report_finding "FG-2.1.4" "$title" "$description" "Medium" "Pass" "Planned" "NTP synchronization is enabled. Auditor: Verify NTP server (e.g., pool.ntp.org) is appropriate."
    else
        report_finding "FG-2.1.4" "$title" "$description" "Medium" "Fail" "Quick" "Enable NTP: 'config system ntp' 'set ntpsync enable' 'set server <ntp_server>' 'end'. Auditor: Verify NTP server settings."
    fi
}

control_8() { # 2.1.5 Ensure hostname is set (Automated)
    local title="Ensure hostname is set"
    local description="Configures a unique hostname for device identification and management."
    if grep -q "set hostname " "$CONFIG_FILE" 2>/dev/null; then
        report_finding "FG-2.1.5" "$title" "$description" "Medium" "Pass" "Planned" "Hostname is configured. Auditor: Verify hostname is unique and matches inventory."
    else
        report_finding "FG-2.1.5" "$title" "$description" "High" "Fail" "Quick" "Configure hostname: 'config system global' 'set hostname <unique_name>' 'end'. Auditor: Verify hostname uniqueness."
    fi
}

control_9() { # 2.1.6 Ensure the latest firmware is installed (Manual)
    local title="Ensure latest firmware is installed"
    local description="Keeps the firewall firmware up-to-date to address security vulnerabilities and bugs."
    report_finding "FG-2.1.6" "$title" "$description" "Critical" "Manual" "Involved" "Auditor: Check firmware version in GUI (Dashboard > Status > System Information) or CLI ('get system status'). Compare with https://www.fortiguard.com/psirt?product=FortiOS. Follow Fortinet’s recommended upgrade path if outdated."
}

control_10() { # 2.1.7 Disable USB Firmware and configuration installation (Automated)
    local title="Disable USB firmware and configuration installation"
    local description="Prevents automatic installation from USB to avoid unauthorized changes."
    if grep -A 10 "config system auto-install" "$CONFIG_FILE" | grep -q "set auto-install-config disable" 2>/dev/null && \
       grep -A 10 "config system auto-install" "$CONFIG_FILE" | grep -q "set auto-install-image disable" 2>/dev/null; then
        report_finding "FG-2.1.7" "$title" "$description" "High" "Pass" "Planned" "USB auto-install is disabled. Auditor: Confirm setting."
    else
        report_finding "FG-2.1.7" "$title" "$description" "High" "Fail" "Quick" "Disable USB auto-install: 'config system auto-install' 'set auto-install-config disable' 'set auto-install-image disable' 'end'. Auditor: Verify settings."
    fi
}

control_11() { # 2.1.8 Disable static keys for TLS (Automated)
    local title="Disable static keys for TLS"
    local description="Ensures strong cryptographic settings by disabling static TLS keys."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set strong-crypto enable" 2>/dev/null; then
        report_finding "FG-2.1.8" "$title" "$description" "High" "Pass" "Planned" "Static keys for TLS are disabled. Auditor: Confirm strong-crypto setting."
    else
        report_finding "FG-2.1.8" "$title" "$description" "High" "Fail" "Quick" "Disable static keys: 'config system global' 'set strong-crypto enable' 'end'. Auditor: Verify setting."
    fi
}

control_12() { # 2.1.9 Enable Global Strong Encryption (Automated)
    local title="Enable global strong encryption"
    local description="Enforces strong encryption protocols globally to enhance security."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set strong-crypto enable" 2>/dev/null; then
        report_finding "FG-2.1.9" "$title" "$description" "High" "Pass" "Planned" "Global strong encryption is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-2.1.9" "$title" "$description" "High" "Fail" "Quick" "Enable strong encryption: 'config system global' 'set strong-crypto enable' 'end'. Auditor: Verify setting."
    fi
}

control_13() { # 2.1.10 Ensure management GUI listens on secure TLS version (Manual)
    local title="Ensure management GUI uses secure TLS version"
    local description="Restricts management GUI to secure TLS versions (e.g., TLS 1.2/1.3) to prevent vulnerabilities."
    report_finding "FG-2.1.10" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI TLS version in CLI ('config system global' 'show' to verify 'ssl-min-proto-ver tls1-2' or higher). Ensure only secure TLS versions (e.g., TLS 1.2/1.3) are used. Update verdict."
}

control_14() { # 2.1.11 Ensure CDN is enabled for improved GUI performance (Manual)
    local title="Ensure CDN is enabled for GUI performance"
    local description="Enables Content Delivery Network for faster GUI performance."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set gui-cdn-usage enable" 2>/dev/null; then
        report_finding "FG-2.1.11" "$title" "$description" "Low" "Pass" "Planned" "GUI CDN is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-2.1.11" "$title" "$description" "Low" "Manual" "Quick" "Auditor: Check GUI (System > Settings, verify CDN enabled) or CLI ('config system global' 'set gui-cdn-usage enable' 'end'). Update verdict."
    fi
}

control_15() { # 2.1.12 Ensure single CPU core overloaded event is logged (Manual)
    local title="Ensure single CPU core overload logging"
    local description="Logs events when a single CPU core is overloaded to monitor performance issues."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set log-single-cpu-high enable" 2>/dev/null; then
        report_finding "FG-2.1.12" "$title" "$description" "Medium" "Pass" "Planned" "Single CPU core overload logging is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-2.1.12" "$title" "$description" "Medium" "Manual" "Quick" "Auditor: Check CLI ('config system global' 'set log-single-cpu-high enable' 'end'). Verify logging in Log & Report. Update verdict."
    fi
}

control_16() { # 2.2.1 Ensure 'Password Policy' is enabled (Automated)
    local title="Ensure password policy is enabled"
    local description="Enforces strong password requirements to enhance account security."
    if grep -A 10 "config system password-policy" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null && \
       grep -A 10 "config system password-policy" "$CONFIG_FILE" | grep -q "set minimum-length [8-9][0-9]*" 2>/dev/null; then
        report_finding "FG-2.2.1" "$title" "$description" "High" "Pass" "Planned" "Password policy is enabled with minimum length >= 8. Auditor: Verify policy settings."
    else
        report_finding "FG-2.2.1" "$title" "$description" "High" "Fail" "Involved" "Enable password policy: 'config system password-policy' 'set status enable' 'set minimum-length 8' 'set min-lower-case-letter 1' 'set min-upper-case-letter 1' 'set min-non-alphanumeric 1' 'set min-number 1' 'end'. Auditor: Verify settings."
    fi
}

control_17() { # 2.2.2 Ensure administrator password retries and lockout time are configured (Automated)
    local title="Ensure admin password retries and lockout"
    local description="Sets limits on password retries and lockout duration to prevent brute-force attacks."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-lockout-threshold 3" 2>/dev/null && \
       grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-lockout-duration 900" 2>/dev/null; then
        report_finding "FG-2.2.2" "$title" "$description" "High" "Pass" "Planned" "Admin lockout threshold (3) and duration (900s) are configured. Auditor: Confirm settings."
    else
        report_finding "FG-2.2.2" "$title" "$description" "High" "Fail" "Quick" "Configure lockout: 'config system global' 'set admin-lockout-threshold 3' 'set admin-lockout-duration 900' 'end'. Auditor: Verify settings."
    fi
}

control_18() { # 2.3.1 Ensure only SNMPv3 is enabled (Automated)
    local title="Ensure only SNMPv3 is enabled"
    local description="Disables insecure SNMPv1/v2c and enables secure SNMPv3 for monitoring."
    if grep -A 10 "config system snmp sysinfo" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null && \
       ! grep -q "config system snmp community" "$CONFIG_FILE" 2>/dev/null; then
        report_finding "FG-2.3.1" "$title" "$description" "High" "Pass" "Planned" "Only SNMPv3 is enabled. Auditor: Confirm no SNMPv1/v2c communities exist."
    else
        report_finding "FG-2.3.1" "$title" "$description" "High" "Fail" "Quick" "Disable SNMPv1/v2c: 'config system snmp community' 'delete <community>' 'end'. Enable SNMPv3: 'config system snmp sysinfo' 'set status enable' 'end'. Auditor: Verify settings."
    fi
}

control_19() { # 2.3.2 Allow only trusted hosts in SNMPv3 (Manual)
    local title="Allow only trusted hosts in SNMPv3"
    local description="Restricts SNMPv3 access to specific trusted hosts to enhance security."
    if grep -A 10 "config system snmp user" "$CONFIG_FILE" | grep -q "set notify-hosts [0-9]\+" 2>/dev/null && \
       ! grep -A 10 "config system snmp user" "$CONFIG_FILE" | grep -q "set notify-hosts 0.0.0.0" 2>/dev/null; then
        report_finding "FG-2.3.2" "$title" "$description" "High" "Pass" "Planned" "SNMPv3 trusted hosts are configured. Auditor: Verify trusted host IPs."
    else
        report_finding "FG-2.3.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (System > SNMP, verify no 0.0.0.0 in Hosts) or CLI ('config system snmp user' 'edit <user>' 'unset notify-hosts 0.0.0.0' 'end'). Update verdict."
    fi
}

control_20() { # 2.4.1 Ensure default 'admin' password is changed (Manual)
    local title="Ensure default admin password is changed"
    local description="Changes the default admin password to prevent unauthorized access."
    report_finding "FG-2.4.1" "$title" "$description" "High" "Manual" "Quick" "Auditor: Verify default admin password is changed in GUI (System > Administrators, edit admin, check password status) or CLI ('config system admin' 'edit admin' 'set password <new_password>' 'end'). Update verdict."
}

control_21() { # 2.4.2 Ensure all login accounts have specific trusted hosts enabled (Manual)
    local title="Ensure trusted hosts for login accounts"
    local description="Restricts admin account access to specific trusted hosts to limit exposure."
    if grep -A 10 "config system admin" "$CONFIG_FILE" | grep -q "set trusthost[1-9]" 2>/dev/null && \
       ! grep -A 10 "config system admin" "$CONFIG_FILE" | grep -q "set trusthost[1-9] 0.0.0.0" 2>/dev/null; then
        report_finding "FG-2.4.2" "$title" "$description" "High" "Pass" "Planned" "Trusted hosts are configured for admin accounts. Auditor: Verify trusted host IPs."
    else
        report_finding "FG-2.4.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (System > Administrators, ensure 'Restrict login to trusted hosts' is enabled) or CLI ('config system admin' 'edit <admin>' 'set trusthost1 <ip> <mask>' 'end'). Update verdict."
    fi
}

control_22() { # 2.4.3 Ensure admin accounts with different privileges have correct profiles assigned (Manual)
    local title="Ensure correct admin profile assignments"
    local description="Assigns appropriate privilege profiles to admin accounts to enforce least privilege."
    report_finding "FG-2.4.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Verify admin profiles in GUI (System > Administrators, check profile assignments) or CLI ('config system accprofile' 'edit <profile>' 'show full'). Ensure least privilege (e.g., tier_1 has read-only for fwgrp). Update verdict."
}

control_23() { # 2.4.4 Ensure idle timeout time is configured (Automated)
    local title="Ensure idle timeout is configured"
    local description="Sets an idle timeout to automatically log out inactive admin sessions."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admintimeout 5" 2>/dev/null; then
        report_finding "FG-2.4.4" "$title" "$description" "Medium" "Pass" "Planned" "Idle timeout is set to 5 minutes. Auditor: Confirm setting."
    else
        report_finding "FG-2.4.4" "$title" "$description" "Medium" "Fail" "Quick" "Set idle timeout: 'config system global' 'set admintimeout 5' 'end'. Auditor: Verify setting."
    fi
}

control_24() { # 2.4.5 Ensure only encrypted access channels are enabled (Automated)
    local title="Ensure only encrypted access channels"
    local description="Allows only secure access protocols (HTTPS, SSH) to protect management interfaces."
    if grep -A 10 "config system interface" "$CONFIG_FILE" | grep -q "set allowaccess.*\(https\|ssh\)" 2>/dev/null && \
       ! grep -A 10 "config system interface" "$CONFIG_FILE" | grep -q "set allowaccess.*\(http\|telnet\)" 2>/dev/null; then
        report_finding "FG-2.4.5" "$title" "$description" "High" "Pass" "Planned" "Only HTTPS and SSH are enabled. Auditor: Confirm no HTTP/Telnet access."
    else
        report_finding "FG-2.4.5" "$title" "$description" "High" "Fail" "Quick" "Enable only HTTPS/SSH: 'config system interface' 'edit <interface>' 'set allowaccess https ssh ping snmp' 'end'. Auditor: Verify settings."
    fi
}

control_25() { # 2.4.6 Apply Local-in Policies (Manual)
    local title="Apply local-in policies"
    local description="Configures local-in policies to control traffic destined to the firewall itself."
    if grep -q "config firewall local-in-policy" "$CONFIG_FILE" 2>/dev/null; then
        report_finding "FG-2.4.6" "$title" "$description" "High" "Pass" "Planned" "Local-in policies are configured. Auditor: Verify policies in CLI ('config firewall local-in-policy' 'show')."
    else
        report_finding "FG-2.4.6" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check CLI ('config firewall local-in-policy' 'edit <id>' 'set intf <interface>' 'set srcaddr <source>' 'set dstaddr <dest>' 'set action deny' 'end'). Update verdict."
    fi
}

control_26() { # 2.4.7 Ensure default Admin ports are changed (Manual)
    local title="Ensure default admin ports are changed"
    local description="Changes default admin ports to non-standard ports to reduce attack surface."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-sport [0-9]\+" 2>/dev/null && \
       ! grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-sport 443" 2>/dev/null; then
        report_finding "FG-2.4.7" "$title" "$description" "High" "Pass" "Planned" "Admin port changed from default 443. Auditor: Verify non-default port."
    else
        report_finding "FG-2.4.7" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check CLI ('config system global' 'set admin-sport <port>' 'end'). Ensure port is not 443. Update verdict."
    fi
}

control_27() { # 2.4.8 Virtual patching on the local-in management interface (Manual)
    local title="Enable virtual patching on management interface"
    local description="Applies virtual patching to protect the management interface from known vulnerabilities."
    if grep -A 10 "config firewall local-in-policy" "$CONFIG_FILE" | grep -q "set virtual-patch enable" 2>/dev/null; then
        report_finding "FG-2.4.8" "$title" "$description" "High" "Pass" "Planned" "Virtual patching is enabled. Auditor: Confirm IPS signatures are applied."
    else
        report_finding "FG-2.4.8" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check CLI ('config firewall local-in-policy' 'edit <id>' 'set virtual-patch enable' 'end'). Update verdict."
    fi
}

control_28() { # 2.5.1 Ensure High Availability configuration is enabled (Automated)
    local title="Ensure High Availability is enabled"
    local description="Configures High Availability to ensure system redundancy and uptime."
    if grep -q "config system ha" "$CONFIG_FILE" 2>/dev/null; then
        report_finding "FG-2.5.1" "$title" "$description" "High" "Pass" "Planned" "HA is configured. Auditor: Verify HA settings ('config system ha' 'show')."
    else
        report_finding "FG-2.5.1" "$title" "$description" "High" "Fail" "Involved" "Enable HA: 'config system ha' 'set group-name <name>' 'set mode a-p' 'set password <pass>' 'set hbdev <interface> 50' 'end'. Auditor: Verify HA setup."
    fi
}

control_29() { # 2.5.2 Ensure 'Monitor Interfaces' for High Availability devices is enabled (Automated)
    local title="Ensure HA monitor interfaces are enabled"
    local description="Configures HA to monitor specific interfaces for failover detection."
    if grep -A 10 "config system ha" "$CONFIG_FILE" | grep -q "set monitor [a-zA-Z0-9]\+" 2>/dev/null; then
        report_finding "FG-2.5.2" "$title" "$description" "High" "Pass" "Planned" "HA monitor interfaces are configured. Auditor: Verify interfaces ('config system ha' 'show')."
    else
        report_finding "FG-2.5.2" "$title" "$description" "High" "Fail" "Quick" "Configure HA monitor: 'config system ha' 'set monitor <interface1> <interface2>' 'end'. Auditor: Verify interfaces."
    fi
}

control_30() { # 2.5.3 Ensure HA Reserved Management Interface is configured (Manual)
    local title="Ensure HA reserved management interface"
    local description="Configures a reserved management interface for HA to ensure management access."
    if grep -A 10 "config system ha" "$CONFIG_FILE" | grep -q "set ha-mgmt-status enable" 2>/dev/null && \
       grep -q "config system ha-mgmt-interfaces" "$CONFIG_FILE" 2>/dev/null; then
        report_finding "FG-2.5.3" "$title" "$description" "High" "Pass" "Planned" "HA reserved management interface is configured. Auditor: Verify interface and gateway."
    else
        report_finding "FG-2.5.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (System > HA, enable Management Interface Reservation) or CLI ('config system ha' 'set ha-mgmt-status enable' 'config ha-mgmt-interfaces' 'edit 1' 'set interface <port>' 'set gateway <ip>' 'end'). Update verdict."
    fi
}

# --- Policy and Objects ---
control_31() { # 3.1 Ensure that unused policies are reviewed regularly (Manual)
    local title="Review unused firewall policies"
    local description="Regularly reviews and removes unused firewall policies to reduce complexity."
    report_finding "FG-3.1" "$title" "$description" "Medium" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, review hit counts) or CLI ('config firewall policy' 'show'). Delete unused policies (hit count 0). Update verdict."
}

control_32() { # 3.2 Ensure that policies do not use 'ALL' as Service (Automated)
    local title="Ensure policies avoid 'ALL' service"
    local description="Restricts firewall policies to specific services to enhance security."
    if ! grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set service \"ALL\"" 2>/dev/null; then
        report_finding "FG-3.2" "$title" "$description" "High" "Pass" "Planned" "No policies use 'ALL' as service. Auditor: Confirm specific services are defined."
    else
        report_finding "FG-3.2" "$title" "$description" "High" "Fail" "Quick" "Modify policies: 'config firewall policy' 'edit <id>' 'set service <specific_service>' 'end'. Auditor: Verify services (e.g., FTP, SNMP)."
    fi
}

control_33() { # 3.3 Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB (Manual)
    local title="Deny Tor and malicious IP traffic"
    local description="Blocks traffic to/from Tor, malicious servers, and scanners using ISDB objects."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set srcaddr.*\(Tor-Exit\.Node\|Tor-Relay\.Node\|Censys-Scanner\|Shodan-Scanner\|Botnet-C\&C\.Server\|Malicious-Malicious\.Server\)" 2>/dev/null && \
       grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set action deny" 2>/dev/null; then
        report_finding "FG-3.3" "$title" "$description" "High" "Pass" "Planned" "Deny policies for Tor/malicious IPs exist. Auditor: Verify ISDB objects."
    else
        report_finding "FG-3.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, verify deny policies for Tor, malicious IPs) or CLI ('config firewall policy' 'edit <id>' 'set srcaddr Tor-Exit.Node Tor-Relay.Node Censys-Scanner Shodan-Scanner Botnet-C\&C.Server Malicious-Malicious.Server' 'set action deny' 'end'). Update verdict."
    fi
}

control_34() { # 3.4 Ensure logging is enabled on all firewall policies (Manual)
    local title="Enable logging on firewall policies"
    local description="Ensures all firewall policies log traffic for auditing and monitoring."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set logtraffic all" 2>/dev/null; then
        report_finding "FG-3.4" "$title" "$description" "High" "Pass" "Planned" "Logging is enabled for firewall policies. Auditor: Verify logging settings."
    else
        report_finding "FG-3.4" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure 'Log Allowed Traffic' and 'Log Violation Traffic' are enabled) or CLI ('config firewall policy' 'edit <id>' 'set logtraffic all' 'end'). Update verdict."
    fi
}

# --- Security Profiles ---
control_35() { # 4.1.1 Detect Botnet connections (Manual)
    local title="Detect and block botnet connections"
    local description="Blocks outgoing connections to known botnet command and control servers."
    if grep -A 10 "config ips sensor" "$CONFIG_FILE" | grep -q "set scan-botnet-connections block" 2>/dev/null; then
        report_finding "FG-4.1.1" "$title" "$description" "High" "Pass" "Planned" "Botnet connection blocking is enabled. Auditor: Verify IPS sensor settings."
    else
        report_finding "FG-4.1.1" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Security Profiles > Intrusion Prevention, ensure 'Scan Outgoing Connections to Botnet Sites' is set to Block) or CLI ('config ips sensor' 'edit <sensor>' 'set scan-botnet-connections block' 'end'). Update verdict."
    fi
}

control_36() { # 4.1.2 Apply IPS Security Profile to Policies (Manual)
    local title="Apply IPS security profile to policies"
    local description="Applies Intrusion Prevention System profiles to firewall policies for threat detection."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set ips-sensor" 2>/dev/null; then
        report_finding "FG-4.1.2" "$title" "$description" "High" "Pass" "Planned" "IPS security profile is applied to policies. Auditor: Verify IPS sensor assignment."
    else
        report_finding "FG-4.1.2" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure IPS profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set ips-sensor <sensor>' 'end'). Update verdict."
    fi
}

control_37() { # 4.2.1 Ensure Antivirus Definition Push Updates are Configured (Automated)
    local title="Ensure antivirus definition updates"
    local description="Configures automatic antivirus definition updates to protect against new threats."
    if grep -A 10 "config system autoupdate schedule" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null && \
       grep -A 10 "config system autoupdate schedule" "$CONFIG_FILE" | grep -q "set frequency automatic" 2>/dev/null; then
        report_finding "FG-4.2.1" "$title" "$description" "High" "Pass" "Planned" "Antivirus definition push updates are enabled. Auditor: Confirm setting."
    else
        report_finding "FG-4.2.1" "$title" "$description" "High" "Fail" "Quick" "Enable AV updates: 'config system autoupdate schedule' 'set status enable' 'set frequency automatic' 'end'. Auditor: Verify setting."
    fi
}

control_38() { # 4.2.2 Apply Antivirus Security Profile to Policies (Manual)
    local title="Apply antivirus security profile to policies"
    local description="Applies antivirus profiles to firewall policies to scan for malware."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set av-profile" 2>/dev/null; then
        report_finding "FG-4.2.2" "$title" "$description" "High" "Pass" "Planned" "Antivirus profile is applied to policies. Auditor: Verify AV profile assignment."
    else
        report_finding "FG-4.2.2" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure AV profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set av-profile <profile>' 'end'). Update verdict."
    fi
}

control_39() { # 4.2.3 Enable Outbreak Prevention Database (Automated)
    local title="Enable outbreak prevention database"
    local description="Enables FortiGuard outbreak prevention to block emerging threats."
    if grep -A 10 "config antivirus profile" "$CONFIG_FILE" | grep -q "set fortiguard-outbreak-prevention enable" 2>/dev/null; then
        report_finding "FG-4.2.3" "$title" "$description" "High" "Pass" "Planned" "Outbreak prevention database is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-4.2.3" "$title" "$description" "High" "Fail" "Quick" "Enable outbreak prevention: 'config antivirus profile' 'edit <profile>' 'set fortiguard-outbreak-prevention enable' 'end'. Auditor: Verify setting."
    fi
}

control_40() { # 4.2.4 Enable AI/heuristic based malware detection (Automated)
    local title="Enable AI/heuristic malware detection"
    local description="Enables AI-based heuristic malware detection to identify unknown threats."
    if grep -A 10 "config antivirus settings" "$CONFIG_FILE" | grep -q "set machine-learning-detection enable" 2>/dev/null; then
        report_finding "FG-4.2.4" "$title" "$description" "High" "Pass" "Planned" "AI/heuristic malware detection is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-4.2.4" "$title" "$description" "High" "Fail" "Quick" "Enable AI detection: 'config antivirus settings' 'set machine-learning-detection enable' 'end'. Auditor: Verify setting."
    fi
}

control_41() { # 4.2.5 Enable grayware detection on antivirus (Automated)
    local title="Enable grayware detection"
    local description="Enables detection of grayware in antivirus profiles to block potentially unwanted programs."
    if grep -A 10 "config antivirus profile" "$CONFIG_FILE" | grep -q "set grayware enable" 2>/dev/null; then
        report_finding "FG-4.2.5" "$title" "$description" "High" "Pass" "Planned" "Grayware detection is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-4.2.5" "$title" "$description" "High" "Fail" "Quick" "Enable grayware detection: 'config antivirus profile' 'edit <profile>' 'set grayware enable' 'end'. Auditor: Verify setting."
    fi
}

control_42() { # 4.2.6 Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled (Manual)
    local title="Enable FortiGuard AI-based sandbox scanning"
    local description="Enables inline scanning with FortiGuard sandbox for advanced threat detection."
    if grep -A 10 "config system fortiguard" "$CONFIG_FILE" | grep -q "set sandbox-inline-scan enable" 2>/dev/null; then
        report_finding "FG-4.2.6" "$title" "$description" "High" "Pass" "Planned" "Inline scanning with FortiGuard AI-Based Sandbox is enabled. Auditor: Verify setting and license."
    else
        report_finding "FG-4.2.6" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (System > Feature Visibility, enable FortiGate Cloud Sandbox; Security Profiles > AntiVirus, set scan strategy to Inline) or CLI ('config system fortiguard' 'set sandbox-inline-scan enable' 'end'). Update verdict."
    fi
}

control_43() { # 4.3.1 Enable Botnet C&C Domain Blocking DNS Filter (Automated)
    local title="Enable botnet C&C domain blocking"
    local description="Blocks DNS queries to known botnet command and control domains."
    if grep -A 10 "config dnsfilter profile" "$CONFIG_FILE" | grep -q "set block-botnet enable" 2>/dev/null; then
        report_finding "FG-4.3.1" "$title" "$description" "High" "Pass" "Planned" "Botnet C&C domain blocking is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-4.3.1" "$title" "$description" "High" "Fail" "Quick" "Enable botnet blocking: 'config dnsfilter profile' 'edit <profile>' 'set block-botnet enable' 'end'. Auditor: Verify setting."
    fi
}

control_44() { # 4.3.2 Ensure DNS Filter logs all DNS queries and responses (Manual)
    local title="Enable DNS query/response logging"
    local description="Logs all DNS queries and responses for monitoring and auditing."
    if grep -A 10 "config dnsfilter profile" "$CONFIG_FILE" | grep -q "set log-all-domain enable" 2>/dev/null; then
        report_finding "FG-4.3.2" "$title" "$description" "High" "Pass" "Planned" "DNS query/response logging is enabled. Auditor: Verify logs in Log & Report."
    else
        report_finding "FG-4.3.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Security Profiles > DNS Filter, enable 'Log all DNS queries and responses') or CLI ('config dnsfilter profile' 'edit <profile>' 'set log-all-domain enable' 'end'). Update verdict."
    fi
}

control_45() { # 4.3.3 Apply DNS Filter Security Profile to Policies (Manual)
    local title="Apply DNS filter to policies"
    local description="Applies DNS filter profiles to firewall policies for enhanced security."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set dnsfilter-profile" 2>/dev/null; then
        report_finding "FG-4.3.3" "$title" "$description" "High" "Pass" "Planned" "DNS filter profile is applied to policies. Auditor: Verify profile assignment."
    else
        report_finding "FG-4.3.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure DNS filter profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set dnsfilter-profile <profile>' 'end'). Update verdict."
    fi
}

control_46() { # 4.4.1 Block high risk categories on Application Control (Manual)
    local title="Block high-risk application categories"
    local description="Blocks high-risk application categories to prevent unauthorized or risky traffic."
    if grep -A 10 "config application list" "$CONFIG_FILE" | grep -q "set action block" 2>/dev/null; then
        report_finding "FG-4.4.1" "$title" "$description" "High" "Pass" "Planned" "High-risk application categories are blocked. Auditor: Verify blocked categories."
    else
        report_finding "FG-4.4.1" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Security Profiles > Application Control, set high-risk categories to Block) or CLI ('config application list' 'edit <list>' 'set action block' for high-risk categories). Update verdict."
    fi
}

control_47() { # 4.4.2 Block applications running on non-default ports (Automated)
    local title="Block applications on non-default ports"
    local description="Enforces application control to block apps running on non-standard ports."
    if grep -A 10 "config application list" "$CONFIG_FILE" | grep -q "set enforce-default-app-port enable" 2>/dev/null; then
        report_finding "FG-4.4.2" "$title" "$description" "High" "Pass" "Planned" "Non-default port application blocking is enabled. Auditor: Confirm setting."
    else
        report_finding "FG-4.4.2" "$title" "$description" "High" "Fail" "Quick" "Enable non-default port blocking: 'config application list' 'edit <list>' 'set enforce-default-app-port enable' 'end'. Auditor: Verify setting."
    fi
}

control_48() { # 4.4.3 Ensure all Application Control related traffic is logged (Manual)
    local title="Ensure application control traffic logging"
    local description="Logs all application control traffic for monitoring and auditing."
    if ! grep -A 10 "config application list" "$CONFIG_FILE" | grep -q "set action allow" 2>/dev/null; then
        report_finding "FG-4.4.3" "$title" "$description" "High" "Pass" "Planned" "No application categories set to Allow. Auditor: Verify all categories are Monitor or Block."
    else
        report_finding "FG-4.4.3" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Security Profiles > Application Control, set all categories to Monitor or Block) or CLI ('config application list' 'edit <list>' 'set action monitor' for categories). Update verdict."
    fi
}

control_49() { # 4.4.4 Apply Application Control Security Profile to Policies (Manual)
    local title="Apply application control to policies"
    local description="Applies application control profiles to firewall policies for traffic monitoring."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set application-list" 2>/dev/null; then
        report_finding "FG-4.4.4" "$title" "$description" "High" "Pass" "Planned" "Application control profile is applied to policies. Auditor: Verify profile assignment."
    else
        report_finding "FG-4.4.4" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure Application Control profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set application-list <list>' 'end'). Update verdict."
    fi
}

# --- Security Fabric ---
control_50() { # 5.1.1 Enable Compromised Host Quarantine (Automated)
    local title="Enable compromised host quarantine"
    local description="Quarantines compromised hosts to prevent further network damage."
    if grep -A 10 "config system automation-action" "$CONFIG_FILE" | grep -q "set action-type quarantine" 2>/dev/null; then
        report_finding "FG-5.1.1" "$title" "$description" "High" "Pass" "Planned" "Compromised host quarantine is enabled. Auditor: Verify automation action settings."
    else
        report_finding "FG-5.1.1" "$title" "$description" "High" "Fail" "Quick" "Enable quarantine: 'config system automation-action' 'edit Quarantine' 'set action-type quarantine' 'end'. Auditor: Verify setting."
    fi
}

control_51() { # 5.2.1.1 Ensure Security Fabric is Configured (Automated)
    local title="Ensure Security Fabric is configured"
    local description="Enables Security Fabric for centralized management and threat intelligence sharing."
    if grep -A 10 "config system csf" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null; then
        report_finding "FG-5.2.1.1" "$title" "$description" "High" "Pass" "Planned" "Security Fabric is configured. Auditor: Verify root FortiGate and FortiAnalyzer settings."
    else
        report_finding "FG-5.2.1.1" "$title" "$description" "High" "Fail" "Involved" "Enable Security Fabric: 'config system csf' 'set status enable' 'set group-name <name>' 'end'. Auditor: Verify configuration."
    fi
}

# --- VPN ---
control_52() { # 6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual)
    local title="Apply trusted certificate for VPN portal"
    local description="Uses a trusted CA-signed certificate for the SSL VPN portal to ensure secure connections."
    if grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set servercert" 2>/dev/null && \
       ! grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set servercert \"self-sign\"" 2>/dev/null; then
        report_finding "FG-6.1.1" "$title" "$description" "High" "Pass" "Planned" "Trusted signed certificate is applied to VPN portal. Auditor: Verify certificate issuer."
    else
        report_finding "FG-6.1.1" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (VPN > SSL-VPN Settings, verify trusted CA certificate) or CLI ('config vpn ssl settings' 'set servercert <cert>' 'end'). Update verdict."
    fi
}

control_53() { # 6.1.2 Enable Limited TLS Versions for SSL VPN (Manual)
    local title="Enable limited TLS versions for SSL VPN"
    local description="Restricts SSL VPN to secure TLS versions (1.2/1.3) to prevent vulnerabilities."
    if grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set ssl-min-proto-ver tls1-2" 2>/dev/null && \
       grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set ssl-max-proto-ver tls1-3" 2>/dev/null; then
        report_finding "FG-6.1.2" "$title" "$description" "High" "Pass" "Planned" "Limited TLS versions (1.2/1.3) are enabled for SSL VPN. Auditor: Confirm settings."
    else
        report_finding "FG-6.1.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check CLI ('config vpn ssl settings' 'set ssl-min-proto-ver tls1-2' 'set ssl-max-proto-ver tls1-3' 'set algorithm high' 'end'). Update verdict."
    fi
}

# --- Logs and Reports ---
control_54() { # 7.1.1 Enable Event Logging (Automated)
    local title="Enable event logging"
    local description="Enables logging of system events for auditing and monitoring."
    if grep -A 10 "config log eventfilter" "$CONFIG_FILE" | grep -q "set event enable" 2>/dev/null; then
        report_finding "FG-7.1.1" "$title" "$description" "High" "Pass" "Planned" "Event logging is enabled. Auditor: Verify logs in Log & Report."
    else
        report_finding "FG-7.1.1" "$title" "$description" "High" "Fail" "Quick" "Enable event logging: 'config log eventfilter' 'set event enable' 'end'. Auditor: Verify logging."
    fi
}

control_55() { # 7.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Automated)
    local title="Encrypt log transmission"
    local description="Ensures log transmission to FortiAnalyzer/FortiManager is encrypted for security."
    if grep -A 10 "config log fortianalyzer setting" "$CONFIG_FILE" | grep -q "set reliable enable" 2>/dev/null && \
       grep -A 10 "config log fortianalyzer setting" "$CONFIG_FILE" | grep -q "set enc-algorithm high" 2>/dev/null; then
        report_finding "FG-7.2.1" "$title" "$description" "High" "Pass" "Planned" "Encrypted log transmission is enabled. Auditor: Verify FortiAnalyzer settings."
    else
        report_finding "FG-7.2.1" "$title" "$description" "High" "Fail" "Quick" "Enable encrypted logs: 'config log fortianalyzer setting' 'set reliable enable' 'set enc-algorithm high' 'end'. Auditor: Verify settings."
    fi
}

control_56() { # 7.3.1 Centralized Logging and Reporting (Automated)
    local title="Enable centralized logging"
    local description="Configures centralized logging to FortiAnalyzer or syslog for comprehensive monitoring."
    if grep -q "config log fortianalyzer setting" "$CONFIG_FILE" 2>/dev/null || \
       grep -q "config log syslogd setting" "$CONFIG_FILE" 2>/dev/null; then
        report_finding "FG-7.3.1" "$title" "$description" "High" "Pass" "Planned" "Centralized logging is configured. Auditor: Verify FortiAnalyzer or syslog settings."
    else
        report_finding "FG-7.3.1" "$title" "$description" "High" "Fail" "Involved" "Configure centralized logging: 'config log fortianalyzer setting' 'set status enable' 'set server <ip>' 'end' or 'config log syslogd setting' 'set status enable' 'set server <ip>' 'end'. Auditor: Verify configuration."
    fi
}

# Run all controls
for i in $(seq 1 56); do
    if type "control_$i" >/dev/null 2>&1; then
        control_$i
    else
        echo "Error: Control function control_$i not found" >&2
        exit 1
    fi
done

# Verify output file is not empty
if [ ! -s "$OUTPUT_FILE" ]; then
    echo "Error: No findings written to '$OUTPUT_FILE'" >&2
    exit 1
fi

# Generate HTML report
cat << EOF > "${OUTPUT_FILE%.txt}.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS FortiGate Firewall 7.0.x Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .pass { color: green; }
        .fail { color: red; }
        .manual { color: orange; }
    </style>
</head>
<body>
    <h1>CIS FortiGate Firewall 7.0.x Benchmark Report</h1>
    <table>
        <tr>
            <th>Finding ID</th>
            <th>Title</th>
            <th>Description</th>
            <th>Risk</th>
            <th>Status</th>
            <th>Fix Type</th>
            <th>Remediation</th>
        </tr>
EOF

while IFS=';' read -r line; do
    FINDING_ID=$(echo "$line" | grep -oP 'FINDING_ID=\K[^;]+')
    TITLE=$(echo "$line" | grep -oP 'TITLE=\K[^;]+')
    DESCRIPTION=$(echo "$line" | grep -oP 'DESCRIPTION=\K[^;]+')
    RISK=$(echo "$line" | grep -oP 'RISK=\K[^;]+')
    STATUS=$(echo "$line" | grep -oP 'STATUS=\K[^;]+')
    FIX_TYPE=$(echo "$line" | grep -oP 'FIX_TYPE=\K[^;]+')
    REMEDIATION=$(echo "$line" | grep -oP 'REMEDIATION=\K.*$')

    case "$STATUS" in
        "Pass") STATUS_CLASS="pass" ;;
        "Fail") STATUS_CLASS="fail" ;;
        "Manual") STATUS_CLASS="manual" ;;
        *) STATUS_CLASS="" ;;
    esac

    cat << EOF >> "${OUTPUT_FILE%.txt}.html"
        <tr>
            <td>$FINDING_ID</td>
            <td>$TITLE</td>
            <td>$DESCRIPTION</td>
            <td>$RISK</td>
            <td class="$STATUS_CLASS">$STATUS</td>
            <td>$FIX_TYPE</td>
            <td>$REMEDIATION</td>
        </tr>
EOF
done < "$OUTPUT_FILE"

cat << EOF >> "${OUTPUT_FILE%.txt}.html"
    </table>
</body>
</html>
EOF

exit 0
