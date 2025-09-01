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
    local id="$1" title="$2" description="$3" risk="$4" status="$5" fix_type="$6" remediation="$7" business_impact="$8"
    echo "FINDING_ID=$id;TITLE=$title;DESCRIPTION=$description;RISK=$risk;STATUS=$status;FIX_TYPE=$fix_type;REMEDIATION=$remediation;BUSINESS_IMPACT=$business_impact" >> "$OUTPUT_FILE"
}

# --- Network Settings ---
control_1() { # 1.1 Ensure DNS server is configured (Automated)
    local business_impact="Without configured DNS servers, the firewall may experience unreliable name resolution, leading to service disruptions, failed security updates, and potential exposure to DNS-based attacks, resulting in operational downtime and increased security risks."
    if grep -A 10 "config system dns" "$CONFIG_FILE" | grep -q "set primary 8.8.8.8" 2>/dev/null && \
       grep -A 10 "config system dns" "$CONFIG_FILE" | grep -q "set secondary 8.8.4.4" 2>/dev/null; then
        local title="DNS Server Configured (Compliant)"
        local description="DNS servers are properly configured, ensuring reliable name resolution for network operations."
        report_finding "FG-1.1" "$title" "$description" "Medium" "Pass" "Planned" "DNS servers are configured (8.8.8.8, 8.8.4.4). Auditor: Verify these are appropriate for your environment." "$business_impact"
    else
        local title="DNS Server Not Configured"
        local description="DNS servers are not configured, which can lead to failures in name resolution and affect various network functions."
        report_finding "FG-1.1" "$title" "$description" "Medium" "Fail" "Quick" "Configure DNS servers: 'config system dns' 'set primary 8.8.8.8' 'set secondary 8.8.4.4' 'end'. Auditor: Verify DNS server addresses." "$business_impact"
    fi
}

control_2() { # 1.2 Ensure intra-zone traffic is not always allowed (Manual)
    local business_impact="Allowing unrestricted intra-zone traffic can enable lateral movement by attackers within the network, leading to data breaches, unauthorized access, and potential financial losses from compromised internal resources."
    if grep -A 10 "config system zone" "$CONFIG_FILE" | grep -q "set intrazone block" 2>/dev/null; then
        local title="Intra-Zone Traffic Blocked (Compliant)"
        local description="Intra-zone traffic is blocked, aligning with secure network segmentation policies."
        report_finding "FG-1.2" "$title" "$description" "High" "Pass" "Planned" "Intra-zone traffic is blocked. Auditor: Confirm this aligns with network policy." "$business_impact"
    else
        local title="Intra-Zone Traffic Allowed"
        local description="Intra-zone traffic is not blocked, potentially allowing unauthorized communication within zones."
        report_finding "FG-1.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Network > Interfaces, select zone, ensure 'Block intra-zone traffic' is enabled) or CLI ('config system zone' 'edit <zone>' 'set intrazone block' 'end'). Update verdict based on findings." "$business_impact"
    fi
}

control_3() { # 1.3 Disable all management related services on WAN port (Manual)
    local business_impact="Enabling management services on WAN ports exposes the device to remote attacks, potentially leading to unauthorized access, data theft, and service disruptions, causing significant financial and reputational damage."
    if ! grep -A 10 "config system interface" "$CONFIG_FILE" | grep -q "set allowaccess.*\(http\|telnet\|snmp\|radius-acct\)" 2>/dev/null; then
        local title="Management Services Disabled on WAN Port (Compliant)"
        local description="No insecure management services are enabled on the WAN interface, reducing external attack surface."
        report_finding "FG-1.3" "$title" "$description" "High" "Pass" "Planned" "No management services (HTTP, Telnet, SNMP, Radius) enabled on WAN interface. Auditor: Confirm WAN interface settings." "$business_impact"
    else
        local title="Management Services Enabled on WAN Port"
        local description="Insecure management services are enabled on the WAN interface, increasing vulnerability to external threats."
        report_finding "FG-1.3" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Network > Interfaces, select WAN, ensure HTTP, Telnet, SNMP, Radius are disabled) or CLI ('config system interface' 'edit <wan>' 'unset allowaccess http telnet snmp radius-acct' 'end'). Update verdict." "$business_impact"
    fi
}

# --- System Settings ---
control_4() { # 2.1.1 Ensure 'Pre-Login Banner' is set (Automated)
    local business_impact="Without a pre-login banner, users may not be aware of legal notices or usage policies, potentially leading to compliance violations and legal risks for the organization."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set pre-login-banner enable" 2>/dev/null; then
        local title="Pre-Login Banner Enabled (Compliant)"
        local description="Pre-login banner is enabled, providing necessary notices before authentication."
        report_finding "FG-2.1.1" "$title" "$description" "Low" "Pass" "Planned" "Pre-login banner is enabled. Auditor: Verify banner content in GUI (System > Replacement Messages > Pre-login Disclaimer Message)." "$business_impact"
    else
        local title="Pre-Login Banner Disabled"
        local description="Pre-login banner is not enabled, missing an opportunity to display important notices."
        report_finding "FG-2.1.1" "$title" "$description" "Low" "Fail" "Quick" "Enable pre-login banner: 'config system global' 'set pre-login-banner enable' 'end'. Auditor: Configure and verify banner content." "$business_impact"
    fi
}

control_5() { # 2.1.2 Ensure 'Post-Login-Banner' is set (Automated)
    local business_impact="Absence of a post-login banner can result in users not being reminded of policies after login, increasing the risk of policy violations and associated compliance issues."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set post-login-banner enable" 2>/dev/null; then
        local title="Post-Login Banner Enabled (Compliant)"
        local description="Post-login banner is enabled, reinforcing notices after successful authentication."
        report_finding "FG-2.1.2" "$title" "$description" "Low" "Pass" "Planned" "Post-login banner is enabled. Auditor: Verify banner content in GUI (System > Replacement Messages > Post-login Disclaimer Message)." "$business_impact"
    else
        local title="Post-Login Banner Disabled"
        local description="Post-login banner is not enabled, potentially leaving users uninformed post-authentication."
        report_finding "FG-2.1.2" "$title" "$description" "Low" "Fail" "Quick" "Enable post-login banner: 'config system global' 'set post-login-banner enable' 'end'. Auditor: Configure and verify banner content." "$business_impact"
    fi
}

control_6() { # 2.1.3 Ensure timezone is properly configured (Manual)
    local business_impact="Incorrect timezone configuration can lead to misaligned timestamps in logs, complicating incident response and compliance auditing, potentially resulting in regulatory fines."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set timezone [0-9]\+" 2>/dev/null; then
        local title="Timezone Properly Configured (Compliant)"
        local description="Timezone is set correctly, ensuring accurate time-based operations and logging."
        report_finding "FG-2.1.3" "$title" "$description" "Low" "Pass" "Planned" "Timezone is configured. Auditor: Verify timezone ID (e.g., 12 for Eastern Time) matches environment." "$business_impact"
    else
        local title="Timezone Not Properly Configured"
        local description="Timezone is not configured, which may cause inaccuracies in time-sensitive functions."
        report_finding "FG-2.1.3" "$title" "$description" "Low" "Manual" "Quick" "Auditor: Check GUI (System > Settings, verify timezone) or CLI ('config system global' 'set timezone <ID>' 'end'). Use 'set timezone ?' for ID list. Update verdict." "$business_impact"
    fi
}

control_7() { # 2.1.4 Ensure correct system time is configured through NTP (Automated)
    local business_impact="Without NTP synchronization, time drifts can occur, leading to inaccurate logs, failed certificate validations, and synchronization issues in distributed systems, causing operational errors and security vulnerabilities."
    if grep -A 10 "config system ntp" "$CONFIG_FILE" | grep -q "set ntpsync enable" 2>/dev/null; then
        local title="NTP Configured (Compliant)"
        local description="NTP is enabled, maintaining accurate system time for logging and operations."
        report_finding "FG-2.1.4" "$title" "$description" "Medium" "Pass" "Planned" "NTP synchronization is enabled. Auditor: Verify NTP server (e.g., pool.ntp.org) is appropriate." "$business_impact"
    else
        local title="NTP Not Configured"
        local description="NTP synchronization is not enabled, risking time inaccuracies across the system."
        report_finding "FG-2.1.4" "$title" "$description" "Medium" "Fail" "Quick" "Enable NTP: 'config system ntp' 'set ntpsync enable' 'set server <ntp_server>' 'end'. Auditor: Verify NTP server settings." "$business_impact"
    fi
}

control_8() { # 2.1.5 Ensure hostname is set (Automated)
    local business_impact="Without a unique hostname, device identification in networks and logs becomes difficult, leading to confusion in management, delayed incident response, and potential misconfiguration errors."
    if grep -q "set hostname " "$CONFIG_FILE" 2>/dev/null; then
        local title="Hostname Set (Compliant)"
        local description="Hostname is configured, aiding in device identification and management."
        report_finding "FG-2.1.5" "$title" "$description" "Medium" "Pass" "Planned" "Hostname is configured. Auditor: Verify hostname is unique and matches inventory." "$business_impact"
    else
        local title="Hostname Not Set"
        local description="Hostname is not configured, which can complicate device management and logging."
        report_finding "FG-2.1.5" "$title" "$description" "High" "Fail" "Quick" "Configure hostname: 'config system global' 'set hostname <unique_name>' 'end'. Auditor: Verify hostname uniqueness." "$business_impact"
    fi
}

control_9() { # 2.1.6 Ensure the latest firmware is installed (Manual)
    local title="Manual Review: Latest Firmware Installation"
    local description="Verify that the latest firmware is installed to address known vulnerabilities and ensure optimal performance."
    local business_impact="Running outdated firmware exposes the system to known security vulnerabilities, potentially leading to data breaches, system compromise, and significant financial losses."
    report_finding "FG-2.1.6" "$title" "$description" "Critical" "Manual" "Involved" "Auditor: Check firmware version in GUI (Dashboard > Status > System Information) or CLI ('get system status'). Compare with https://www.fortiguard.com/psirt?product=FortiOS. Follow Fortinet’s recommended upgrade path if outdated." "$business_impact"
}

control_10() { # 2.1.7 Disable USB Firmware and configuration installation (Automated)
    local business_impact="Enabling USB auto-install can allow unauthorized firmware or configuration changes, leading to malware infection or misconfiguration, resulting in network downtime and security breaches."
    if grep -A 10 "config system auto-install" "$CONFIG_FILE" | grep -q "set auto-install-config disable" 2>/dev/null && \
       grep -A 10 "config system auto-install" "$CONFIG_FILE" | grep -q "set auto-install-image disable" 2>/dev/null; then
        local title="USB Auto-Install Disabled (Compliant)"
        local description="USB firmware and configuration installation is disabled, preventing unauthorized changes."
        report_finding "FG-2.1.7" "$title" "$description" "High" "Pass" "Planned" "USB auto-install is disabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="USB Auto-Install Enabled"
        local description="USB auto-install is not disabled, risking unauthorized firmware or config installations."
        report_finding "FG-2.1.7" "$title" "$description" "High" "Fail" "Quick" "Disable USB auto-install: 'config system auto-install' 'set auto-install-config disable' 'set auto-install-image disable' 'end'. Auditor: Verify settings." "$business_impact"
    fi
}

control_11() { # 2.1.8 Disable static keys for TLS (Automated)
    local business_impact="Using static keys for TLS can compromise encryption, leading to data interception, privacy breaches, and non-compliance with security standards, resulting in legal penalties."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set strong-crypto enable" 2>/dev/null; then
        local title="Static Keys for TLS Disabled (Compliant)"
        local description="Static keys are disabled, enforcing stronger cryptographic practices."
        report_finding "FG-2.1.8" "$title" "$description" "High" "Pass" "Planned" "Static keys for TLS are disabled. Auditor: Confirm strong-crypto setting." "$business_impact"
    else
        local title="Static Keys for TLS Enabled"
        local description="Static keys for TLS are not disabled, weakening encryption security."
        report_finding "FG-2.1.8" "$title" "$description" "High" "Fail" "Quick" "Disable static keys: 'config system global' 'set strong-crypto enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_12() { # 2.1.9 Enable Global Strong Encryption (Automated)
    local business_impact="Without strong encryption, data transmissions are vulnerable to interception and tampering, leading to data leaks, intellectual property theft, and regulatory non-compliance."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set strong-crypto enable" 2>/dev/null; then
        local title="Global Strong Encryption Enabled (Compliant)"
        local description="Strong encryption is enabled globally, enhancing data protection."
        report_finding "FG-2.1.9" "$title" "$description" "High" "Pass" "Planned" "Global strong encryption is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Global Strong Encryption Disabled"
        local description="Global strong encryption is not enabled, reducing overall security posture."
        report_finding "FG-2.1.9" "$title" "$description" "High" "Fail" "Quick" "Enable strong encryption: 'config system global' 'set strong-crypto enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_13() { # 2.1.10 Ensure management GUI listens on secure TLS version (Manual)
    local title="Manual Review: Secure TLS for Management GUI"
    local description="Verify that the management GUI uses secure TLS versions to prevent vulnerabilities."
    local business_impact="Using insecure TLS versions for management can expose credentials and configurations to attacks, leading to unauthorized access and potential network compromise."
    report_finding "FG-2.1.10" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI TLS version in CLI ('config system global' 'show' to verify 'ssl-min-proto-ver tls1-2' or higher). Ensure only secure TLS versions (e.g., TLS 1.2/1.3) are used. Update verdict." "$business_impact"
}

control_14() { # 2.1.11 Ensure CDN is enabled for improved GUI performance (Manual)
    local business_impact="Disabling CDN can lead to slower GUI performance, reducing administrator efficiency and potentially delaying response to security incidents."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set gui-cdn-usage enable" 2>/dev/null; then
        local title="GUI CDN Enabled (Compliant)"
        local description="CDN is enabled, improving GUI loading times and performance."
        report_finding "FG-2.1.11" "$title" "$description" "Low" "Pass" "Planned" "GUI CDN is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="GUI CDN Disabled"
        local description="CDN for GUI is not enabled, which may degrade performance."
        report_finding "FG-2.1.11" "$title" "$description" "Low" "Manual" "Quick" "Auditor: Check GUI (System > Settings, verify CDN enabled) or CLI ('config system global' 'set gui-cdn-usage enable' 'end'). Update verdict." "$business_impact"
    fi
}

control_15() { # 2.1.12 Ensure single CPU core overloaded event is logged (Manual)
    local business_impact="Not logging CPU overload events can delay detection of performance issues, leading to system instability, service outages, and lost productivity."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set log-single-cpu-high enable" 2>/dev/null; then
        local title="Single CPU Core Overload Logging Enabled (Compliant)"
        local description="Logging for single CPU core overload is enabled, aiding in performance monitoring."
        report_finding "FG-2.1.12" "$title" "$description" "Medium" "Pass" "Planned" "Single CPU core overload logging is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Single CPU Core Overload Logging Disabled"
        local description="Logging for single CPU core overload is not enabled, missing key performance alerts."
        report_finding "FG-2.1.12" "$title" "$description" "Medium" "Manual" "Quick" "Auditor: Check CLI ('config system global' 'set log-single-cpu-high enable' 'end'). Verify logging in Log & Report. Update verdict." "$business_impact"
    fi
}

control_16() { # 2.2.1 Ensure 'Password Policy' is enabled (Automated)
    local business_impact="Weak password policies can lead to account compromises through brute-force or guessing attacks, resulting in data breaches and unauthorized access to sensitive systems."
    if grep -A 10 "config system password-policy" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null && \
       grep -A 10 "config system password-policy" "$CONFIG_FILE" | grep -q "set minimum-length [8-9][0-9]*" 2>/dev/null; then
        local title="Password Policy Enabled (Compliant)"
        local description="Password policy is enabled with adequate complexity requirements."
        report_finding "FG-2.2.1" "$title" "$description" "High" "Pass" "Planned" "Password policy is enabled with minimum length >= 8. Auditor: Verify policy settings." "$business_impact"
    else
        local title="Password Policy Disabled"
        local description="Password policy is not enabled, allowing weak passwords to be used."
        report_finding "FG-2.2.1" "$title" "$description" "High" "Fail" "Involved" "Enable password policy: 'config system password-policy' 'set status enable' 'set minimum-length 8' 'set min-lower-case-letter 1' 'set min-upper-case-letter 1' 'set min-non-alphanumeric 1' 'set min-number 1' 'end'. Auditor: Verify settings." "$business_impact"
    fi
}

control_17() { # 2.2.2 Ensure administrator password retries and lockout time are configured (Automated)
    local business_impact="Inadequate lockout policies can facilitate brute-force attacks, leading to unauthorized admin access and potential full system compromise."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-lockout-threshold 3" 2>/dev/null && \
       grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-lockout-duration 900" 2>/dev/null; then
        local title="Admin Password Retries and Lockout Configured (Compliant)"
        local description="Lockout threshold and duration are set, protecting against brute-force attempts."
        report_finding "FG-2.2.2" "$title" "$description" "High" "Pass" "Planned" "Admin lockout threshold (3) and duration (900s) are configured. Auditor: Confirm settings." "$business_impact"
    else
        local title="Admin Password Retries and Lockout Not Configured"
        local description="Lockout policies for admin passwords are not configured, increasing brute-force risk."
        report_finding "FG-2.2.2" "$title" "$description" "High" "Fail" "Quick" "Configure lockout: 'config system global' 'set admin-lockout-threshold 3' 'set admin-lockout-duration 900' 'end'. Auditor: Verify settings." "$business_impact"
    fi
}

control_18() { # 2.3.1 Ensure only SNMPv3 is enabled (Automated)
    local business_impact="Using insecure SNMP versions can expose network configurations and credentials to interception, leading to unauthorized monitoring or control of devices."
    if grep -A 10 "config system snmp sysinfo" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null && \
       ! grep -q "config system snmp community" "$CONFIG_FILE" 2>/dev/null; then
        local title="Only SNMPv3 Enabled (Compliant)"
        local description="SNMPv3 is enabled without insecure v1/v2c communities."
        report_finding "FG-2.3.1" "$title" "$description" "High" "Pass" "Planned" "Only SNMPv3 is enabled. Auditor: Confirm no SNMPv1/v2c communities exist." "$business_impact"
    else
        local title="Insecure SNMP Versions Enabled"
        local description="SNMPv1/v2c may be enabled, posing security risks due to lack of encryption."
        report_finding "FG-2.3.1" "$title" "$description" "High" "Fail" "Quick" "Disable SNMPv1/v2c: 'config system snmp community' 'delete <community>' 'end'. Enable SNMPv3: 'config system snmp sysinfo' 'set status enable' 'end'. Auditor: Verify settings." "$business_impact"
    fi
}

control_19() { # 2.3.2 Allow only trusted hosts in SNMPv3 (Manual)
    local business_impact="Allowing untrusted hosts in SNMP can lead to unauthorized queries or modifications, potentially exposing sensitive network information."
    if grep -A 10 "config system snmp user" "$CONFIG_FILE" | grep -q "set notify-hosts [0-9]\+" 2>/dev/null && \
       ! grep -A 10 "config system snmp user" "$CONFIG_FILE" | grep -q "set notify-hosts 0.0.0.0" 2>/dev/null; then
        local title="Only Trusted Hosts Allowed in SNMPv3 (Compliant)"
        local description="SNMPv3 is restricted to trusted hosts, enhancing security."
        report_finding "FG-2.3.2" "$title" "$description" "High" "Pass" "Planned" "SNMPv3 trusted hosts are configured. Auditor: Verify trusted host IPs." "$business_impact"
    else
        local title="Untrusted Hosts Allowed in SNMPv3"
        local description="SNMPv3 may allow access from untrusted or any hosts, increasing exposure."
        report_finding "FG-2.3.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (System > SNMP, verify no 0.0.0.0 in Hosts) or CLI ('config system snmp user' 'edit <user>' 'unset notify-hosts 0.0.0.0' 'end'). Update verdict." "$business_impact"
    fi
}

control_20() { # 2.4.1 Ensure default 'admin' password is changed (Manual)
    local title="Manual Review: Default Admin Password Changed"
    local description="Verify that the default admin password has been changed to prevent unauthorized access."
    local business_impact="Retaining the default admin password allows easy unauthorized access, leading to full system control and potential data breaches."
    report_finding "FG-2.4.1" "$title" "$description" "High" "Manual" "Quick" "Auditor: Verify default admin password is changed in GUI (System > Administrators, edit admin, check password status) or CLI ('config system admin' 'edit admin' 'set password <new_password>' 'end'). Update verdict." "$business_impact"
}

control_21() { # 2.4.2 Ensure all login accounts have specific trusted hosts enabled (Manual)
    local business_impact="Without trusted hosts, admin accounts are exposed to login attempts from anywhere, increasing the risk of brute-force attacks and unauthorized access."
    if grep -A 10 "config system admin" "$CONFIG_FILE" | grep -q "set trusthost[1-9]" 2>/dev/null && \
       ! grep -A 10 "config system admin" "$CONFIG_FILE" | grep -q "set trusthost[1-9] 0.0.0.0" 2>/dev/null; then
        local title="Trusted Hosts Enabled for Login Accounts (Compliant)"
        local description="All admin accounts are restricted to trusted hosts."
        report_finding "FG-2.4.2" "$title" "$description" "High" "Pass" "Planned" "Trusted hosts are configured for admin accounts. Auditor: Verify trusted host IPs." "$business_impact"
    else
        local title="Trusted Hosts Not Enabled for Login Accounts"
        local description="Admin accounts may not be restricted to trusted hosts, broadening attack surface."
        report_finding "FG-2.4.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (System > Administrators, ensure 'Restrict login to trusted hosts' is enabled) or CLI ('config system admin' 'edit <admin>' 'set trusthost1 <ip> <mask>' 'end'). Update verdict." "$business_impact"
    fi
}

control_22() { # 2.4.3 Ensure admin accounts with different privileges have correct profiles assigned (Manual)
    local title="Manual Review: Correct Admin Profile Assignments"
    local description="Verify that admin accounts have appropriate privilege profiles assigned based on roles."
    local business_impact="Incorrect profile assignments can lead to excessive privileges, enabling insider threats or accidental misconfigurations with severe operational impacts."
    report_finding "FG-2.4.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Verify admin profiles in GUI (System > Administrators, check profile assignments) or CLI ('config system accprofile' 'edit <profile>' 'show full'). Ensure least privilege (e.g., tier_1 has read-only for fwgrp). Update verdict." "$business_impact"
}

control_23() { # 2.4.4 Ensure idle timeout time is configured (Automated)
    local business_impact="Long idle timeouts can leave sessions open, allowing unauthorized use if a device is left unattended, leading to data exposure or malicious actions."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admintimeout 5" 2>/dev/null; then
        local title="Idle Timeout Configured (Compliant)"
        local description="Idle timeout is set to 5 minutes, securing against unattended sessions."
        report_finding "FG-2.4.4" "$title" "$description" "Medium" "Pass" "Planned" "Idle timeout is set to 5 minutes. Auditor: Confirm setting." "$business_impact"
    else
        local title="Idle Timeout Not Configured"
        local description="Idle timeout is not set to the recommended value, risking open sessions."
        report_finding "FG-2.4.4" "$title" "$description" "Medium" "Fail" "Quick" "Set idle timeout: 'config system global' 'set admintimeout 5' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_24() { # 2.4.5 Ensure only encrypted access channels are enabled (Automated)
    local business_impact="Enabling unencrypted channels like HTTP/Telnet exposes credentials and data to interception, leading to account compromise and data breaches."
    if grep -A 10 "config system interface" "$CONFIG_FILE" | grep -q "set allowaccess.*\(https\|ssh\)" 2>/dev/null && \
       ! grep -A 10 "config system interface" "$CONFIG_FILE" | grep -q "set allowaccess.*\(http\|telnet\)" 2>/dev/null; then
        local title="Only Encrypted Access Channels Enabled (Compliant)"
        local description="Only HTTPS and SSH are allowed, ensuring secure management access."
        report_finding "FG-2.4.5" "$title" "$description" "High" "Pass" "Planned" "Only HTTPS and SSH are enabled. Auditor: Confirm no HTTP/Telnet access." "$business_impact"
    else
        local title="Unencrypted Access Channels Enabled"
        local description="Insecure channels like HTTP or Telnet may be enabled, compromising security."
        report_finding "FG-2.4.5" "$title" "$description" "High" "Fail" "Quick" "Enable only HTTPS/SSH: 'config system interface' 'edit <interface>' 'set allowaccess https ssh ping snmp' 'end'. Auditor: Verify settings." "$business_impact"
    fi
}

control_25() { # 2.4.6 Apply Local-in Policies (Manual)
    local business_impact="Without local-in policies, traffic to the firewall itself is not controlled, potentially allowing unauthorized access or DoS attacks."
    if grep -q "config firewall local-in-policy" "$CONFIG_FILE" 2>/dev/null; then
        local title="Local-in Policies Applied (Compliant)"
        local description="Local-in policies are configured to control traffic to the device."
        report_finding "FG-2.4.6" "$title" "$description" "High" "Pass" "Planned" "Local-in policies are configured. Auditor: Verify policies in CLI ('config firewall local-in-policy' 'show')." "$business_impact"
    else
        local title="Local-in Policies Not Applied"
        local description="No local-in policies are configured, leaving device traffic uncontrolled."
        report_finding "FG-2.4.6" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check CLI ('config firewall local-in-policy' 'edit <id>' 'set intf <interface>' 'set srcaddr <source>' 'set dstaddr <dest>' 'set action deny' 'end'). Update verdict." "$business_impact"
    fi
}

control_26() { # 2.4.7 Ensure default Admin ports are changed (Manual)
    local business_impact="Using default admin ports makes the device easier to target for attacks, increasing the likelihood of successful reconnaissance and exploitation."
    if grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-sport [0-9]\+" 2>/dev/null && \
       ! grep -A 10 "config system global" "$CONFIG_FILE" | grep -q "set admin-sport 443" 2>/dev/null; then
        local title="Default Admin Ports Changed (Compliant)"
        local description="Admin ports have been changed from defaults, obscuring from standard scans."
        report_finding "FG-2.4.7" "$title" "$description" "High" "Pass" "Planned" "Admin port changed from default 443. Auditor: Verify non-default port." "$business_impact"
    else
        local title="Default Admin Ports Not Changed"
        local description="Admin ports are set to defaults, making them predictable for attackers."
        report_finding "FG-2.4.7" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check CLI ('config system global' 'set admin-sport <port>' 'end'). Ensure port is not 443. Update verdict." "$business_impact"
    fi
}

control_27() { # 2.4.8 Virtual patching on the local-in management interface (Manual)
    local business_impact="Without virtual patching, known vulnerabilities in the management interface remain exploitable, leading to potential device compromise."
    if grep -A 10 "config firewall local-in-policy" "$CONFIG_FILE" | grep -q "set virtual-patch enable" 2>/dev/null; then
        local title="Virtual Patching Enabled on Management Interface (Compliant)"
        local description="Virtual patching is applied, protecting against known vulnerabilities."
        report_finding "FG-2.4.8" "$title" "$description" "High" "Pass" "Planned" "Virtual patching is enabled. Auditor: Confirm IPS signatures are applied." "$business_impact"
    else
        local title="Virtual Patching Disabled on Management Interface"
        local description="Virtual patching is not enabled, leaving the interface vulnerable."
        report_finding "FG-2.4.8" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check CLI ('config firewall local-in-policy' 'edit <id>' 'set virtual-patch enable' 'end'). Update verdict." "$business_impact"
    fi
}

control_28() { # 2.5.1 Ensure High Availability configuration is enabled (Automated)
    local business_impact="Without HA, a single point of failure can cause network outages, leading to business downtime and revenue loss."
    if grep -q "config system ha" "$CONFIG_FILE" 2>/dev/null; then
        local title="High Availability Configured (Compliant)"
        local description="HA is enabled, providing redundancy and failover capabilities."
        report_finding "FG-2.5.1" "$title" "$description" "High" "Pass" "Planned" "HA is configured. Auditor: Verify HA settings ('config system ha' 'show')." "$business_impact"
    else
        local title="High Availability Not Configured"
        local description="HA is not configured, risking single points of failure."
        report_finding "FG-2.5.1" "$title" "$description" "High" "Fail" "Involved" "Enable HA: 'config system ha' 'set group-name <name>' 'set mode a-p' 'set password <pass>' 'set hbdev <interface> 50' 'end'. Auditor: Verify HA setup." "$business_impact"
    fi
}

control_29() { # 2.5.2 Ensure 'Monitor Interfaces' for High Availability devices is enabled (Automated)
    local business_impact="Not monitoring interfaces in HA can delay failover, prolonging outages and impacting business continuity."
    if grep -A 10 "config system ha" "$CONFIG_FILE" | grep -q "set monitor [a-zA-Z0-9]\+" 2>/dev/null; then
        local title="HA Monitor Interfaces Enabled (Compliant)"
        local description="Interfaces are monitored for HA, ensuring prompt failover."
        report_finding "FG-2.5.2" "$title" "$description" "High" "Pass" "Planned" "HA monitor interfaces are configured. Auditor: Verify interfaces ('config system ha' 'show')." "$business_impact"
    else
        local title="HA Monitor Interfaces Disabled"
        local description="No interfaces are monitored for HA, potentially delaying failover."
        report_finding "FG-2.5.2" "$title" "$description" "High" "Fail" "Quick" "Configure HA monitor: 'config system ha' 'set monitor <interface1> <interface2>' 'end'. Auditor: Verify interfaces." "$business_impact"
    fi
}

control_30() { # 2.5.3 Ensure HA Reserved Management Interface is configured (Manual)
    local business_impact="Without a reserved management interface in HA, accessing individual units during failover can be challenging, complicating troubleshooting and increasing downtime."
    if grep -A 10 "config system ha" "$CONFIG_FILE" | grep -q "set ha-mgmt-status enable" 2>/dev/null && \
       grep -q "config system ha-mgmt-interfaces" "$CONFIG_FILE" 2>/dev/null; then
        local title="HA Reserved Management Interface Configured (Compliant)"
        local description="Reserved management interface is set for HA, ensuring accessibility."
        report_finding "FG-2.5.3" "$title" "$description" "High" "Pass" "Planned" "HA reserved management interface is configured. Auditor: Verify interface and gateway." "$business_impact"
    else
        local title="HA Reserved Management Interface Not Configured"
        local description="No reserved management interface for HA, potentially hindering management during issues."
        report_finding "FG-2.5.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (System > HA, enable Management Interface Reservation) or CLI ('config system ha' 'set ha-mgmt-status enable' 'config ha-mgmt-interfaces' 'edit 1' 'set interface <port>' 'set gateway <ip>' 'end'). Update verdict." "$business_impact"
    fi
}

# --- Policy and Objects ---
control_31() { # 3.1 Ensure that unused policies are reviewed regularly (Manual)
    local title="Manual Review: Unused Policies Reviewed"
    local description="Regularly review and remove unused firewall policies to maintain an efficient and secure policy set."
    local business_impact="Accumulation of unused policies can complicate management, increase the risk of misconfigurations, and slow down policy enforcement."
    report_finding "FG-3.1" "$title" "$description" "Medium" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, review hit counts) or CLI ('config firewall policy' 'show'). Delete unused policies (hit count 0). Update verdict." "$business_impact"
}

control_32() { # 3.2 Ensure that policies do not use 'ALL' as Service (Automated)
    local business_impact="Using 'ALL' services in policies allows unnecessary traffic, increasing the attack surface and potential for exploits."
    if ! grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set service \"ALL\"" 2>/dev/null; then
        local title="Policies Avoid 'ALL' Service (Compliant)"
        local description="Firewall policies use specific services, adhering to least privilege."
        report_finding "FG-3.2" "$title" "$description" "High" "Pass" "Planned" "No policies use 'ALL' as service. Auditor: Confirm specific services are defined." "$business_impact"
    else
        local title="Policies Use 'ALL' Service"
        local description="Some policies use 'ALL' as service, broadly allowing traffic."
        report_finding "FG-3.2" "$title" "$description" "High" "Fail" "Quick" "Modify policies: 'config firewall policy' 'edit <id>' 'set service <specific_service>' 'end'. Auditor: Verify services (e.g., FTP, SNMP)." "$business_impact"
    fi
}

control_33() { # 3.3 Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB (Manual)
    local business_impact="Failing to block Tor and malicious IPs can allow command and control communications or scanning, leading to data exfiltration or breaches."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set srcaddr.*\(Tor-Exit\.Node\|Tor-Relay\.Node\|Censys-Scanner\|Shodan-Scanner\|Botnet-C\&C\.Server\|Malicious-Malicious\.Server\)" 2>/dev/null && \
       grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set action deny" 2>/dev/null; then
        local title="Policy Denying Tor/Malicious Traffic (Compliant)"
        local description="Policies are in place to deny traffic from known malicious sources."
        report_finding "FG-3.3" "$title" "$description" "High" "Pass" "Planned" "Deny policies for Tor/malicious IPs exist. Auditor: Verify ISDB objects." "$business_impact"
    else
        local title="No Policy Denying Tor/Malicious Traffic"
        local description="Lack of deny policies for Tor and malicious IPs exposes the network."
        report_finding "FG-3.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, verify deny policies for Tor, malicious IPs) or CLI ('config firewall policy' 'edit <id>' 'set srcaddr Tor-Exit.Node Tor-Relay.Node Censys-Scanner Shodan-Scanner Botnet-C\&C.Server Malicious-Malicious.Server' 'set action deny' 'end'). Update verdict." "$business_impact"
    fi
}

control_34() { # 3.4 Ensure logging is enabled on all firewall policies (Manual)
    local business_impact="Without policy logging, traffic patterns and security events go unrecorded, hindering incident detection and forensic analysis."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set logtraffic all" 2>/dev/null; then
        local title="Logging Enabled on Firewall Policies (Compliant)"
        local description="All firewall policies have logging enabled for comprehensive monitoring."
        report_finding "FG-3.4" "$title" "$description" "High" "Pass" "Planned" "Logging is enabled for firewall policies. Auditor: Verify logging settings." "$business_impact"
    else
        local title="Logging Disabled on Some Firewall Policies"
        local description="Not all policies have logging enabled, reducing visibility."
        report_finding "FG-3.4" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure 'Log Allowed Traffic' and 'Log Violation Traffic' are enabled) or CLI ('config firewall policy' 'edit <id>' 'set logtraffic all' 'end'). Update verdict." "$business_impact"
    fi
}

# --- Security Profiles ---
control_35() { # 4.1.1 Detect Botnet connections (Manual)
    local business_impact="Failing to block botnet connections can allow malware to communicate with C&C servers, leading to data theft or further infections."
    if grep -A 10 "config ips sensor" "$CONFIG_FILE" | grep -q "set scan-botnet-connections block" 2>/dev/null; then
        local title="Botnet Connections Detection Enabled (Compliant)"
        local description="Botnet connections are set to be blocked in IPS."
        report_finding "FG-4.1.1" "$title" "$description" "High" "Pass" "Planned" "Botnet connection blocking is enabled. Auditor: Verify IPS sensor settings." "$business_impact"
    else
        local title="Botnet Connections Detection Disabled"
        local description="Botnet connection scanning is not set to block, allowing potential C&C traffic."
        report_finding "FG-4.1.1" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Security Profiles > Intrusion Prevention, ensure 'Scan Outgoing Connections to Botnet Sites' is set to Block) or CLI ('config ips sensor' 'edit <sensor>' 'set scan-botnet-connections block' 'end'). Update verdict." "$business_impact"
    fi
}

control_36() { # 4.1.2 Apply IPS Security Profile to Policies (Manual)
    local business_impact="Without IPS profiles applied, known exploits and intrusions may go undetected, leading to system compromises."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set ips-sensor" 2>/dev/null; then
        local title="IPS Profile Applied to Policies (Compliant)"
        local description="IPS security profiles are applied to firewall policies."
        report_finding "FG-4.1.2" "$title" "$description" "High" "Pass" "Planned" "IPS security profile is applied to policies. Auditor: Verify IPS sensor assignment." "$business_impact"
    else
        local title="IPS Profile Not Applied to Policies"
        local description="No IPS profiles are applied to policies, missing intrusion prevention."
        report_finding "FG-4.1.2" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure IPS profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set ips-sensor <sensor>' 'end'). Update verdict." "$business_impact"
    fi
}

control_37() { # 4.2.1 Ensure Antivirus Definition Push Updates are Configured (Automated)
    local business_impact="Outdated antivirus definitions leave the system vulnerable to new malware, potentially leading to infections and data loss."
    if grep -A 10 "config system autoupdate schedule" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null && \
       grep -A 10 "config system autoupdate schedule" "$CONFIG_FILE" | grep -q "set frequency automatic" 2>/dev/null; then
        local title="Antivirus Updates Configured (Compliant)"
        local description="Automatic antivirus definition updates are enabled."
        report_finding "FG-4.2.1" "$title" "$description" "High" "Pass" "Planned" "Antivirus definition push updates are enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Antivirus Updates Not Configured"
        local description="Antivirus definition updates are not set to automatic, risking outdated protection."
        report_finding "FG-4.2.1" "$title" "$description" "High" "Fail" "Quick" "Enable AV updates: 'config system autoupdate schedule' 'set status enable' 'set frequency automatic' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_38() { # 4.2.2 Apply Antivirus Security Profile to Policies (Manual)
    local business_impact="Without antivirus profiles, malware can propagate through the network, causing data corruption or theft."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set av-profile" 2>/dev/null; then
        local title="Antivirus Profile Applied to Policies (Compliant)"
        local description="Antivirus security profiles are applied to firewall policies."
        report_finding "FG-4.2.2" "$title" "$description" "High" "Pass" "Planned" "Antivirus profile is applied to policies. Auditor: Verify AV profile assignment." "$business_impact"
    else
        local title="Antivirus Profile Not Applied to Policies"
        local description="No antivirus profiles are applied, leaving traffic unscanned for malware."
        report_finding "FG-4.2.2" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure AV profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set av-profile <profile>' 'end'). Update verdict." "$business_impact"
    fi
}

control_39() { # 4.2.3 Enable Outbreak Prevention Database (Automated)
    local business_impact="Disabling outbreak prevention misses emerging threats, allowing rapid-spreading malware to infect systems."
    if grep -A 10 "config antivirus profile" "$CONFIG_FILE" | grep -q "set fortiguard-outbreak-prevention enable" 2>/dev/null; then
        local title="Outbreak Prevention Enabled (Compliant)"
        local description="FortiGuard outbreak prevention database is enabled."
        report_finding "FG-4.2.3" "$title" "$description" "High" "Pass" "Planned" "Outbreak prevention database is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Outbreak Prevention Disabled"
        local description="Outbreak prevention database is not enabled, reducing defense against new threats."
        report_finding "FG-4.2.3" "$title" "$description" "High" "Fail" "Quick" "Enable outbreak prevention: 'config antivirus profile' 'edit <profile>' 'set fortiguard-outbreak-prevention enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_40() { # 4.2.4 Enable AI/heuristic based malware detection (Automated)
    local business_impact="Without AI/heuristic detection, unknown malware variants may evade signature-based scanning, leading to infections."
    if grep -A 10 "config antivirus settings" "$CONFIG_FILE" | grep -q "set machine-learning-detection enable" 2>/dev/null; then
        local title="AI/Heuristic Malware Detection Enabled (Compliant)"
        local description="AI-based heuristic detection is enabled for advanced threat identification."
        report_finding "FG-4.2.4" "$title" "$description" "High" "Pass" "Planned" "AI/heuristic malware detection is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="AI/Heuristic Malware Detection Disabled"
        local description="AI/heuristic detection is not enabled, limiting protection against unknown threats."
        report_finding "FG-4.2.4" "$title" "$description" "High" "Fail" "Quick" "Enable AI detection: 'config antivirus settings' 'set machine-learning-detection enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_41() { # 4.2.5 Enable grayware detection on antivirus (Automated)
    local business_impact="Ignoring grayware can allow potentially unwanted programs to degrade performance or introduce risks."
    if grep -A 10 "config antivirus profile" "$CONFIG_FILE" | grep -q "set grayware enable" 2>/dev/null; then
        local title="Grayware Detection Enabled (Compliant)"
        local description="Grayware detection is enabled in antivirus profiles."
        report_finding "FG-4.2.5" "$title" "$description" "High" "Pass" "Planned" "Grayware detection is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Grayware Detection Disabled"
        local description="Grayware detection is not enabled, allowing potentially harmful programs."
        report_finding "FG-4.2.5" "$title" "$description" "High" "Fail" "Quick" "Enable grayware detection: 'config antivirus profile' 'edit <profile>' 'set grayware enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_42() { # 4.2.6 Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled (Manual)
    local business_impact="Without sandbox scanning, suspicious files may execute malware, leading to system infections and data compromise."
    if grep -A 10 "config system fortiguard" "$CONFIG_FILE" | grep -q "set sandbox-inline-scan enable" 2>/dev/null; then
        local title="Inline Sandbox Scanning Enabled (Compliant)"
        local description="Inline scanning with FortiGuard AI-based sandbox is enabled."
        report_finding "FG-4.2.6" "$title" "$description" "High" "Pass" "Planned" "Inline scanning with FortiGuard AI-Based Sandbox is enabled. Auditor: Verify setting and license." "$business_impact"
    else
        local title="Inline Sandbox Scanning Disabled"
        local description="Inline sandbox scanning is not enabled, missing advanced threat analysis."
        report_finding "FG-4.2.6" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (System > Feature Visibility, enable FortiGate Cloud Sandbox; Security Profiles > AntiVirus, set scan strategy to Inline) or CLI ('config system fortiguard' 'set sandbox-inline-scan enable' 'end'). Update verdict." "$business_impact"
    fi
}

control_43() { # 4.3.1 Enable Botnet C&C Domain Blocking DNS Filter (Automated)
    local business_impact="Not blocking botnet domains allows infected devices to communicate with attackers, facilitating data exfiltration."
    if grep -A 10 "config dnsfilter profile" "$CONFIG_FILE" | grep -q "set block-botnet enable" 2>/dev/null; then
        local title="Botnet C&C Domain Blocking Enabled (Compliant)"
        local description="DNS filter blocks botnet C&C domains."
        report_finding "FG-4.3.1" "$title" "$description" "High" "Pass" "Planned" "Botnet C&C domain blocking is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Botnet C&C Domain Blocking Disabled"
        local description="Botnet C&C domain blocking is not enabled in DNS filter."
        report_finding "FG-4.3.1" "$title" "$description" "High" "Fail" "Quick" "Enable botnet blocking: 'config dnsfilter profile' 'edit <profile>' 'set block-botnet enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_44() { # 4.3.2 Ensure DNS Filter logs all DNS queries and responses (Manual)
    local business_impact="Not logging DNS queries misses opportunities to detect malicious domain access or anomalies."
    if grep -A 10 "config dnsfilter profile" "$CONFIG_FILE" | grep -q "set log-all-domain enable" 2>/dev/null; then
        local title="DNS Query/Response Logging Enabled (Compliant)"
        local description="All DNS queries and responses are logged for analysis."
        report_finding "FG-4.3.2" "$title" "$description" "High" "Pass" "Planned" "DNS query/response logging is enabled. Auditor: Verify logs in Log & Report." "$business_impact"
    else
        local title="DNS Query/Response Logging Disabled"
        local description="DNS queries and responses are not fully logged, reducing visibility."
        report_finding "FG-4.3.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Security Profiles > DNS Filter, enable 'Log all DNS queries and responses') or CLI ('config dnsfilter profile' 'edit <profile>' 'set log-all-domain enable' 'end'). Update verdict." "$business_impact"
    fi
}

control_45() { # 4.3.3 Apply DNS Filter Security Profile to Policies (Manual)
    local business_impact="Without DNS filter profiles, malicious domains may not be blocked, allowing phishing or malware distribution."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set dnsfilter-profile" 2>/dev/null; then
        local title="DNS Filter Applied to Policies (Compliant)"
        local description="DNS filter security profiles are applied to firewall policies."
        report_finding "FG-4.3.3" "$title" "$description" "High" "Pass" "Planned" "DNS filter profile is applied to policies. Auditor: Verify profile assignment." "$business_impact"
    else
        local title="DNS Filter Not Applied to Policies"
        local description="No DNS filter profiles are applied, missing domain-level protection."
        report_finding "FG-4.3.3" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure DNS filter profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set dnsfilter-profile <profile>' 'end'). Update verdict." "$business_impact"
    fi
}

control_46() { # 4.4.1 Block high risk categories on Application Control (Manual)
    local business_impact="Allowing high-risk applications can introduce vulnerabilities or unauthorized data flows, leading to security incidents."
    if grep -A 10 "config application list" "$CONFIG_FILE" | grep -q "set action block" 2>/dev/null; then
        local title="High-Risk Application Categories Blocked (Compliant)"
        local description="High-risk categories are blocked in application control."
        report_finding "FG-4.4.1" "$title" "$description" "High" "Pass" "Planned" "High-risk application categories are blocked. Auditor: Verify blocked categories." "$business_impact"
    else
        local title="High-Risk Application Categories Not Blocked"
        local description="High-risk application categories are not set to block, allowing potentially dangerous traffic."
        report_finding "FG-4.4.1" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Security Profiles > Application Control, set high-risk categories to Block) or CLI ('config application list' 'edit <list>' 'set action block' for high-risk categories). Update verdict." "$business_impact"
    fi
}

control_47() { # 4.4.2 Block applications running on non-default ports (Automated)
    local business_impact="Allowing applications on non-default ports can enable evasion techniques, bypassing security controls."
    if grep -A 10 "config application list" "$CONFIG_FILE" | grep -q "set enforce-default-app-port enable" 2>/dev/null; then
        local title="Applications on Non-Default Ports Blocked (Compliant)"
        local description="Enforcement of default app ports is enabled, blocking evasions."
        report_finding "FG-4.4.2" "$title" "$description" "High" "Pass" "Planned" "Non-default port application blocking is enabled. Auditor: Confirm setting." "$business_impact"
    else
        local title="Applications on Non-Default Ports Not Blocked"
        local description="Non-default port enforcement is not enabled, allowing potential evasions."
        report_finding "FG-4.4.2" "$title" "$description" "High" "Fail" "Quick" "Enable non-default port blocking: 'config application list' 'edit <list>' 'set enforce-default-app-port enable' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_48() { # 4.4.3 Ensure all Application Control related traffic is logged (Manual)
    local business_impact="Not logging application traffic reduces visibility into usage, hindering detection of anomalies or policy violations."
    if ! grep -A 10 "config application list" "$CONFIG_FILE" | grep -q "set action allow" 2>/dev/null; then
        local title="Application Control Traffic Logged (Compliant)"
        local description="All application categories are set to monitor or block, ensuring logging."
        report_finding "FG-4.4.3" "$title" "$description" "High" "Pass" "Planned" "No application categories set to Allow. Auditor: Verify all categories are Monitor or Block." "$business_impact"
    else
        local title="Application Control Traffic Not Fully Logged"
        local description="Some categories are set to allow without logging, missing traffic records."
        report_finding "FG-4.4.3" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check GUI (Security Profiles > Application Control, set all categories to Monitor or Block) or CLI ('config application list' 'edit <list>' 'set action monitor' for categories). Update verdict." "$business_impact"
    fi
}

control_49() { # 4.4.4 Apply Application Control Security Profile to Policies (Manual)
    local business_impact="Without application control, unauthorized or risky apps can run, leading to data leaks or exploits."
    if grep -A 10 "config firewall policy" "$CONFIG_FILE" | grep -q "set application-list" 2>/dev/null; then
        local title="Application Control Applied to Policies (Compliant)"
        local description="Application control profiles are applied to firewall policies."
        report_finding "FG-4.4.4" "$title" "$description" "High" "Pass" "Planned" "Application control profile is applied to policies. Auditor: Verify profile assignment." "$business_impact"
    else
        local title="Application Control Not Applied to Policies"
        local description="No application control profiles are applied, allowing unchecked app traffic."
        report_finding "FG-4.4.4" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (Policy & Objects > Firewall Policy, ensure Application Control profile is applied) or CLI ('config firewall policy' 'edit <id>' 'set application-list <list>' 'end'). Update verdict." "$business_impact"
    fi
}

# --- Security Fabric ---
control_50() { # 5.1.1 Enable Compromised Host Quarantine (Automated)
    local business_impact="Not quarantining compromised hosts allows threats to spread, potentially causing widespread infections and data loss."
    if grep -A 10 "config system automation-action" "$CONFIG_FILE" | grep -q "set action-type quarantine" 2>/dev/null; then
        local title="Compromised Host Quarantine Enabled (Compliant)"
        local description="Automation for quarantining compromised hosts is enabled."
        report_finding "FG-5.1.1" "$title" "$description" "High" "Pass" "Planned" "Compromised host quarantine is enabled. Auditor: Verify automation action settings." "$business_impact"
    else
        local title="Compromised Host Quarantine Disabled"
        local description="Quarantine for compromised hosts is not enabled, risking threat propagation."
        report_finding "FG-5.1.1" "$title" "$description" "High" "Fail" "Quick" "Enable quarantine: 'config system automation-action' 'edit Quarantine' 'set action-type quarantine' 'end'. Auditor: Verify setting." "$business_impact"
    fi
}

control_51() { # 5.2.1.1 Ensure Security Fabric is Configured (Automated)
    local business_impact="Without Security Fabric, centralized threat intelligence and management are lacking, slowing response to threats."
    if grep -A 10 "config system csf" "$CONFIG_FILE" | grep -q "set status enable" 2>/dev/null; then
        local title="Security Fabric Configured (Compliant)"
        local description="Security Fabric is enabled for integrated security management."
        report_finding "FG-5.2.1.1" "$title" "$description" "High" "Pass" "Planned" "Security Fabric is configured. Auditor: Verify root FortiGate and FortiAnalyzer settings." "$business_impact"
    else
        local title="Security Fabric Not Configured"
        local description="Security Fabric is not enabled, missing out on coordinated security features."
        report_finding "FG-5.2.1.1" "$title" "$description" "High" "Fail" "Involved" "Enable Security Fabric: 'config system csf' 'set status enable' 'set group-name <name>' 'end'. Auditor: Verify configuration." "$business_impact"
    fi
}

# --- VPN ---
control_52() { # 6.1.1 Apply a Trusted Signed Certificate for VPN Portal (Manual)
    local business_impact="Using self-signed certificates can lead to man-in-the-middle attacks, compromising VPN connections and sensitive data."
    if grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set servercert" 2>/dev/null && \
       ! grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set servercert \"self-sign\"" 2>/dev/null; then
        local title="Trusted Certificate Applied to VPN Portal (Compliant)"
        local description="A trusted signed certificate is used for the VPN portal."
        report_finding "FG-6.1.1" "$title" "$description" "High" "Pass" "Planned" "Trusted signed certificate is applied to VPN portal. Auditor: Verify certificate issuer." "$business_impact"
    else
        local title="No Trusted Certificate for VPN Portal"
        local description="VPN portal may use self-signed or no certificate, risking insecure connections."
        report_finding "FG-6.1.1" "$title" "$description" "High" "Manual" "Involved" "Auditor: Check GUI (VPN > SSL-VPN Settings, verify trusted CA certificate) or CLI ('config vpn ssl settings' 'set servercert <cert>' 'end'). Update verdict." "$business_impact"
    fi
}

control_53() { # 6.1.2 Enable Limited TLS Versions for SSL VPN (Manual)
    local business_impact="Allowing outdated TLS versions in VPN can expose sessions to known vulnerabilities, leading to data interception."
    if grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set ssl-min-proto-ver tls1-2" 2>/dev/null && \
       grep -A 10 "config vpn ssl settings" "$CONFIG_FILE" | grep -q "set ssl-max-proto-ver tls1-3" 2>/dev/null; then
        local title="Limited TLS Versions Enabled for SSL VPN (Compliant)"
        local description="SSL VPN is restricted to secure TLS 1.2/1.3 versions."
        report_finding "FG-6.1.2" "$title" "$description" "High" "Pass" "Planned" "Limited TLS versions (1.2/1.3) are enabled for SSL VPN. Auditor: Confirm settings." "$business_impact"
    else
        local title="Unlimited or Insecure TLS Versions for SSL VPN"
        local description="SSL VPN may allow insecure TLS versions, compromising connection security."
        report_finding "FG-6.1.2" "$title" "$description" "High" "Manual" "Quick" "Auditor: Check CLI ('config vpn ssl settings' 'set ssl-min-proto-ver tls1-2' 'set ssl-max-proto-ver tls1-3' 'set algorithm high' 'end'). Update verdict." "$business_impact"
    fi
}

# --- Logs and Reports ---
control_54() { # 7.1.1 Enable Event Logging (Automated)
    local business_impact="Disabling event logging prevents detection and analysis of security events, leading to undetected breaches, compliance failures, and inability to perform root cause analysis, resulting in potential financial penalties and reputational harm."
    if grep -A 10 "config log eventfilter" "$CONFIG_FILE" | grep -q "set event enable" 2>/dev/null; then
        local title="Event Logging Enabled (Compliant)"
        local description="Event logging is enabled, ensuring system events are recorded for auditing and monitoring."
        report_finding "FG-7.1.1" "$title" "$description" "High" "Pass" "Planned" "Event logging is enabled. Auditor: Verify logs in Log & Report." "$business_impact"
    else
        local title="Event Logging Disabled"
        local description="Event logging is disabled, meaning no records of system events are kept, which impairs security monitoring and incident response."
        report_finding "FG-7.1.1" "$title" "$description" "High" "Fail" "Quick" "Enable event logging: 'config log eventfilter' 'set event enable' 'end'. Auditor: Verify logging." "$business_impact"
    fi
}

control_55() { # 7.2.1 Encrypt Log Transmission to FortiAnalyzer / FortiManager (Automated)
    local business_impact="Unencrypted log transmission exposes sensitive log data to interception, potentially revealing security weaknesses or compliance data."
    if grep -A 10 "config log fortianalyzer setting" "$CONFIG_FILE" | grep -q "set reliable enable" 2>/dev/null && \
       grep -A 10 "config log fortianalyzer setting" "$CONFIG_FILE" | grep -q "set enc-algorithm high" 2>/dev/null; then
        local title="Encrypted Log Transmission Enabled (Compliant)"
        local description="Logs are transmitted encrypted to FortiAnalyzer/FortiManager."
        report_finding "FG-7.2.1" "$title" "$description" "High" "Pass" "Planned" "Encrypted log transmission is enabled. Auditor: Verify FortiAnalyzer settings." "$business_impact"
    else
        local title="Encrypted Log Transmission Disabled"
        local description="Log transmission is not encrypted, risking data exposure."
        report_finding "FG-7.2.1" "$title" "$description" "High" "Fail" "Quick" "Enable encrypted logs: 'config log fortianalyzer setting' 'set reliable enable' 'set enc-algorithm high' 'end'. Auditor: Verify settings." "$business_impact"
    fi
}

control_56() { # 7.3.1 Centralized Logging and Reporting (Automated)
    local business_impact="Lack of centralized logging fragments visibility, delaying threat detection and response, and complicating compliance reporting."
    if grep -q "config log fortianalyzer setting" "$CONFIG_FILE" 2>/dev/null || \
       grep -q "config log syslogd setting" "$CONFIG_FILE" 2>/dev/null; then
        local title="Centralized Logging Configured (Compliant)"
        local description="Centralized logging to FortiAnalyzer or syslog is enabled."
        report_finding "FG-7.3.1" "$title" "$description" "High" "Pass" "Planned" "Centralized logging is configured. Auditor: Verify FortiAnalyzer or syslog settings." "$business_impact"
    else
        local title="Centralized Logging Not Configured"
        local description="No centralized logging setup, leading to decentralized log management."
        report_finding "FG-7.3.1" "$title" "$description" "High" "Fail" "Involved" "Configure centralized logging: 'config log fortianalyzer setting' 'set status enable' 'set server <ip>' 'end' or 'config log syslogd setting' 'set status enable' 'set server <ip>' 'end'. Auditor: Verify configuration." "$business_impact"
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
            <th>Business Impact</th>
        </tr>
EOF

while IFS=';' read -r line; do
    FINDING_ID=$(echo "$line" | grep -oP 'FINDING_ID=\K[^;]+')
    TITLE=$(echo "$line" | grep -oP 'TITLE=\K[^;]+')
    DESCRIPTION=$(echo "$line" | grep -oP 'DESCRIPTION=\K[^;]+')
    RISK=$(echo "$line" | grep -oP 'RISK=\K[^;]+')
    STATUS=$(echo "$line" | grep -oP 'STATUS=\K[^;]+')
    FIX_TYPE=$(echo "$line" | grep -oP 'FIX_TYPE=\K[^;]+')
    REMEDIATION=$(echo "$line" | grep -oP 'REMEDIATION=\K[^;]*?(?=;BUSINESS_IMPACT|$)')
    BUSINESS_IMPACT=$(echo "$line" | grep -oP 'BUSINESS_IMPACT=\K.*$')

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
            <td>$BUSINESS_IMPACT</td>
        </tr>
EOF
done < "$OUTPUT_FILE"

cat << EOF >> "${OUTPUT_FILE%.txt}.html"
    </table>
</body>
</html>
EOF

exit 0
