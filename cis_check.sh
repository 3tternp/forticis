#!/usr/bin/env bash
# cis_check_full.sh
# Full CIS FortiGate 7.0.x v1.3.0 config-file auditor
# Adjusted for Windows compatibility via Unix-like shells (e.g., Git Bash)

set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <config_file> <outprefix>" >&2
  exit 2
fi

# --- Path Normalization ---
normalize_path() {
  local p="$1"
  p="${p//\\//}"  # Convert backslashes to forward slashes
  # Remove any surrounding quotes if present
  p="${p#\"}"
  p="${p%\"}"
  if [[ "$p" =~ ^[A-Za-z]:/ ]]; then
    local drive=$(echo "$p" | cut -c1 | tr '[:upper:]' '[:lower:]')
    local rest=$(echo "${p#${p:0:2}}" | sed 's/^\///')  # Remove drive letter and first slash
    echo "/$drive/$rest"
  else
    echo "$p"  # Return quoted for safety
  fi
}

CONFIG="$(normalize_path "$1")"
OUTTXT="$2"  # Direct to $2 for GUI
OUTHTML="${2}.html"  # HTML as $2.html

# Check OS and adjust behavior
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
  echo "Detected Windows environment (e.g., Git Bash). Adjusting path and commands..." >&2
  # Ensure mktemp works on Windows
  if ! command -v mktemp >/dev/null 2>&1; then
    echo "Error: 'mktemp' not found. Install it or use a compatible shell." >&2
    exit 5
  fi
else
  echo "Assuming Unix-like environment. Proceeding with standard checks..." >&2
fi

# Check if file exists, is readable, and handle quoted paths
echo "Checking config file: $CONFIG" >&2
if [[ ! -f "$CONFIG" ]]; then
  echo "Error: Config file not found: $CONFIG" >&2
  exit 3
fi
if [[ ! -r "$CONFIG" ]]; then
  echo "Error: Config file is not readable: $CONFIG. Check permissions with 'chmod 644 $CONFIG' or adjust Windows file attributes." >&2
  exit 4
fi

# Temporary safe copy (adjusted for Windows compatibility)
CFG="$(mktemp -u)"  # Use -u to get filename without creating immediately
trap 'rm -f "$CFG"' EXIT
if ! cp "$CONFIG" "$CFG" 2>/dev/null; then
  echo "Error: Failed to copy config file to temporary location: $CFG. Check write permissions." >&2
  exit 5
fi

# Helpers
escape_html() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import html,sys; print(html.escape(sys.stdin.read()))' 2>/dev/null || { echo "Error in escape_html" >&2; return 1; }
  else
    echo "Warning: python3 not found, using basic escaping." >&2
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g' # Basic HTML escaping
  fi
}

match_regex() {
  local regex="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import re,sys
try:
  content = sys.stdin.read()
  flags = re.MULTILINE | re.DOTALL | re.IGNORECASE
  m = re.search(r'$regex', content, flags)
  if m:
    print("found")
    start = m.start()
    end = m.end()
    lines = content.splitlines(keepends=True)
    line_start = sum(1 for _ in re.finditer(r'\n', content[:start])) - 2
    if line_start < 0: line_start = 0
    line_end = sum(1 for _ in re.finditer(r'\n', content[:end])) + 4  # +3 lines +1
    snippet = ''.join(lines[line_start:line_end])
    print(snippet[:800])  # Limit size
  else:
    print("not found")
except Exception as e:
  print(f"regex_error:{str(e)}")
PY < "$CFG"
  else
    echo "Error: python3 required for regex matching. Install Python or use a Unix-like environment." >&2
    exit 6
  fi
}

# Emit machine line: no trailing ;
emit_line() {
  local id="$1"; shift
  local title="$1"; shift
  local risk="$1"; shift
  local status="$1"; shift
  local fix="$1"; shift
  local evidence="$1"; shift
  local remediation="$@"
  evidence="${evidence//$'\n'/\\n}"
  evidence="${evidence//;/,}"
  remediation="${remediation//$'\n'/\\n}"
  remediation="${remediation//;/,}"
  printf "FINDING_ID=%s;TITLE=%s;RISK=%s;STATUS=%s;FIX_TYPE=%s;EVIDENCE=%s;REMEDIATION=%s\n" \
    "$id" "$title" "$risk" "$status" "$fix" "$evidence" "$remediation" >> "$OUTTXT" 2>/dev/null || { echo "Error writing to $OUTTXT" >&2; return 1; }
}

# HTML header
html_start() {
  cat > "$OUTHTML" <<'HTML' 2>/dev/null || { echo "Error creating HTML file $OUTHTML" >&2; return 1; }
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CIS FortiGate Audit Report</title>
<style>
body{font-family:Inter,Arial,sans-serif;margin:20px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}
th{background:#f4f4f4}
.pass{background:#dff0d8}
.fail{background:#f2dede}
.manual{background:#fcf8e3}
pre{white-space:pre-wrap;word-break:break-word}
.summary{margin-bottom:12px}
</style>
</head>
<body>
<h1>CIS FortiGate 7.0.x v1.3.0 - Audit Report</h1>
<div class="summary">
<p>Source: CIS FortiGate 7.0.x Benchmark v1.3.0.</p>
</div>
<table>
<thead><tr>
<th>Finding ID</th><th>Title</th><th>Risk</th><th>Fix Type</th><th>Status</th><th>Evidence (snippet)</th><th>Remediation (detailed)</th>
</tr></thead>
<tbody>
HTML
}

html_end() {
  cat >> "$OUTHTML" <<'HTML' 2>/dev/null || { echo "Error finalizing HTML file $OUTHTML" >&2; return 1; }
</tbody>
</table>
</body>
</html>
HTML
}

# Clear/create outputs
: > "$OUTTXT" 2>/dev/null || { echo "Error clearing output file $OUTTXT" >&2; exit 6; }
html_start

# -------------------------------------------------------------------------
# CHECKS: id|title|risk|fix_type|auto_regex|pass_when|remediation
# pass_when: "contains" (pass if matches) or "not_contains" (pass if no match)
# auto_regex: "__MANUAL__" for manual
# Use && for multiple required patterns (AND)
# Regex uses . for any char, .*? for non-greedy
# -------------------------------------------------------------------------
read -r -d '' CHECKS <<'EOF' || true
1.1|Ensure DNS server is configured|Medium|Quick|set\s+primary|contains|Configure primary and secondary DNS servers: config system dns; set primary <ip>; set secondary <ip>; end.
1.2|Ensure intra-zone traffic is not always allowed|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify zone policies do not implicitly allow intra-zone traffic unless required. Audit requires review of firewall zones and policies. (CIS Recommendation).
1.3|Disable all management related services on WAN port|High|Planned|config system interface.*?edit.*?wan.*?allowaccess.*?(https|http|ssh|snmp|ping|radius-acct)|not_contains|Review interfaces with role wan or alias WAN and ensure allowaccess does not include http/https/ssh/snmp/ping/radius-acct. CLI: config system interface; edit <wan>; unset allowaccess <service>; next; end.
2.1.1|Ensure 'Pre-Login Banner' is set|Low|Quick|set\s+pre-login-banner\s+enable|contains|Enable pre-login banner: config system global; set pre-login-banner enable; end.
2.1.2|Ensure 'Post-Login-Banner' is set|Low|Quick|set\s+post-login-banner\s+enable|contains|Enable post-login banner: config system global; set post-login-banner enable; end.
2.1.3|Ensure timezone is properly configured|Low|Manual|__MANUAL__|__MANUAL__|Manual: Verify timezone is configured to local timezone and matches logging/monitoring. CLI: config system global; set timezone <region>; end.
2.1.4|Ensure correct system time is configured through NTP|Medium|Quick|set\s+ntpsync\s+enable|contains|Enable NTP: config system ntp; set ntpsync enable; set server <ip>; end.
2.1.5|Ensure hostname is set|Low|Quick|set\s+hostname\s+\S+|contains|Set hostname: config system global; set hostname <name>; end.
2.1.6|Ensure the latest firmware is installed|Low|Manual|__MANUAL__|__MANUAL__|Manual: Verify firmware is current and supported. Check device version against vendor advisories and CIS guidance.
2.1.7|Disable USB Firmware and configuration installation|Medium|Quick|set\s+usb-install\s+disable|contains|Disable USB firmware/config install: config system global; set usb-install disable; end.
2.1.8|Disable static keys for TLS|Medium|Quick|set\s+ssl-static-key\s+disable|contains|Disable static TLS keys: follow FortiOS guidance to remove static TLS keys and use proper certificates.
2.1.9|Enable Global Strong Encryption|Medium|Quick|set\s+strong-crypto\s+enable|contains|Enable strong crypto: config system global; set strong-crypto enable; end.
2.1.10|Ensure management GUI listens on secure TLS version|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify admin-https-ssl-versions includes tlsv1-2 or tlsv1-3. CLI: config system global; set admin-https-ssl-versions tlsv1-3; end.
2.1.11|Ensure CDN is enabled for improved GUI performance|Low|Manual|__MANUAL__|__MANUAL__|Manual: Confirm CDN setting if required by policy.
2.1.12|Ensure single CPU core overloaded event is logged|Low|Manual|__MANUAL__|__MANUAL__|Manual: Ensure device logs CPU/core overload events or monitoring forwarders capture it.
2.2.1|Ensure 'Password Policy' is enabled|High|Quick|set\s+status\s+enable|contains|Enable password policy for administrators: config system password-policy; set status enable; set apply-to administrator; end.
2.2.2|Ensure administrator password retries and lockout time are configured|High|Quick|admin-lockout-threshold&&admin-lockout-duration|contains|Set admin-lockout-threshold >=3 and admin-lockout-duration (seconds) as required: config system global; set admin-lockout-threshold 3; set admin-lockout-duration 600; end.
2.3.1|Ensure only SNMPv3 is enabled|Medium|Planned|config system snmp.*?config community|not_contains|If 'config community' exists, SNMP v1/v2c configured. Disable community entries and use SNMPv3 users: config system snmp; delete community <name>; end.
2.3.2|Allow only trusted hosts in SNMPv3|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify SNMPv3 access is restricted to trusted hosts/subnets.
2.4.1|Ensure default 'admin' password is changed|High|Manual|__MANUAL__|__MANUAL__|Manual: Verify default 'admin' password has been changed; CIS audit procedure includes attempting login without password to verify.
2.4.2|Ensure all the login accounts having specific trusted hosts enabled|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Check 'config system admin' entries for set trusthostN presence and correctness.
2.4.3|Ensure admin accounts with different privileges have their correct profiles assigned|High|Planned|set\s+accprofile|contains|Ensure administrators are assigned least-privilege accprofiles: config system admin; edit <user>; set accprofile <profile>; end.
2.4.4|Ensure idle timeout time is configured|Medium|Quick|admintimeout|contains|Set admintimeout short (e.g., 5-10): config system global; set admintimeout 10; end.
2.4.5|Ensure only encrypted access channels are enabled|High|Quick|set\s+admin-port|not_contains|Ensure management channels use encrypted transport (https/ssh) and disable plaintext where possible; config system global; unset admin-port; end. (Assuming unset disables HTTP)
2.4.6|Apply Local-in Policies|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify local-in policies protect GUI/SSH/other local services; use 'config firewall local-in-policy' to review.
2.4.7|Ensure default Admin ports are changed|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify admin ports changed from defaults if required by policy.
2.4.8|Virtual patching on the local-in management interface|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Check 'config firewall local-in-policy' for set virtual-patch enable where appropriate.
2.5.1|Ensure High Availability configuration is enabled|Low|Quick|set\s+mode|contains|Ensure HA is configured if used: config system ha; set mode a-a; end.
2.5.2|Ensure "Monitor Interfaces" for High Availability devices is enabled|Low|Quick|set\s+monitor|contains|Enable monitor interfaces in HA config.
2.5.3|Ensure HA Reserved Management Interface is configured|Low|Manual|__MANUAL__|__MANUAL__|Manual: Verify reserved management interface exists and is configured for management.
3.1|Ensure that unused policies are reviewed regularly|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Review policy hit counts and disable/delete unused policies per schedule.
3.2|Ensure that policies do not use "ALL" as Service|High|Planned|set\s+service\s+\"?ALL\"?|not_contains|Replace service ALL with least-privilege services: config firewall policy; edit <id>; set service <services>; end.
3.3|Ensure firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Ensure ISDB or threat IP lists used to block Tor/malicious IPs in policies.
3.4|Ensure logging is enabled on all firewall policies|Medium|Planned|set\s+logtraffic\s+all|contains|Ensure policies have logtraffic enabled (set logtraffic all) and logs are forwarded.
4.1.1|Detect Botnet connections|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify IPS profiles detect/block botnet signatures.
4.1.2|Apply IPS Security Profile to Policies|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Validate IPS profiles are applied to relevant firewall policies.
4.2.1|Ensure Antivirus Definition Push Updates are Configured|Medium|Quick|set\s+update|contains|Ensure antivirus signatures/updates configured and scheduled.
4.2.2|Apply Antivirus Security Profile to Policies|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Ensure antivirus profiles applied to policies handling relevant traffic.
4.2.3|Enable Outbreak Prevention Database|Medium|Quick|set\s+outbreak-prevention\s+enable|contains|Enable outbreak prevention DB: config antivirus settings; set outbreak-prevention enable; end.
4.2.4|Enable AI /heuristic based malware detection|Medium|Quick|set\s+ai-based|contains|Enable AI/heuristic detection per FortiGuard options.
4.2.5|Enable grayware detection on antivirus|Medium|Quick|set\s+grayware|contains|Enable grayware detection in AV settings/profiles.
4.2.6|Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify FortiGuard AI Sandbox inline scanning and AV profiles enforce block actions on sandboxed findings.
4.3.1|Enable Botnet C&C Domain Blocking DNS Filter|Medium|Quick|botnet|contains|Enable botnet C&C blocking in DNS Filter profile and apply to policies.
4.3.2|Ensure DNS Filter logs all DNS queries and responses|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Review DNS Filter settings to ensure logging of queries/responses.
4.3.3|Apply DNS Filter Security Profile to Policies|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Ensure DNS Filter profiles applied to relevant policies.
4.4.1|Block high risk categories on Application Control|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Review Application Control profiles to block high risk categories.
4.4.2|Block applications running on non-default ports|Medium|Planned|set\s+enforce-default-app-port\s+enable|contains|Enable enforce-default-app-port (CLI: set enforce-default-app-port enable) in App Control profiles.
4.4.3|Ensure all Application Control related traffic is logged|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Ensure App Control either logs or does not 'Allow' categories silently.
4.4.4|Apply Application Control Security Profile to Policies|Medium|Manual|__MANUAL__|__MANUAL__|Manual: Verify App Control profiles are applied to policies.
5.1.1|Enable Compromised Host Quarantine|High|Quick|set\s+status\s+enable|contains|Enable compromised host quarantine per Security Fabric automation settings.
5.2.1.1|Ensure Security Fabric is Configured|Low|Planned|get system csf|contains|Configure Security Fabric connectors and root FortiGate: follow Fortinet Security Fabric docs.
6.1.1|Apply a Trusted Signed Certificate for VPN Portal|High|Manual|__MANUAL__|__MANUAL__|Manual: Verify SSL VPN portal uses a valid signed certificate (not self-signed) per policy.
6.1.2|Enable Limited TLS Versions for SSL VPN|High|Quick|ssl-min-proto-version|contains|Set ssl-min-proto-version TLS1-2 or TLS1-3: config vpn ssl settings; set ssl-min-proto-version TLS1-2; end.
7.1.1|Enable Event Logging|High|Quick|set\s+event\s+enable|contains|Enable event logging and ensure forwarding/retention: config log setting; set event enable; end.
7.2.1|Encrypt Log Transmission to FortiAnalyzer / FortiManager|Medium|Quick|set\s+secure\s+enable|contains|Enable encryption for log transport to FortiAnalyzer/FortiManager.
7.3.1|Centralized Logging and Reporting|Medium|Planned|set\s+status\s+enable|contains|Configure syslog/FortiAnalyzer and ensure status enable with server configured.
EOF

# Iterate each check
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  IFS='|' read -r FINDING_ID TITLE RISK FIX_TYPE AUTO_REGEX PASS_WHEN REMEDIATION <<< "$line"

  if [[ "$AUTO_REGEX" == "__MANUAL__" ]]; then
    STATUS="manual_review"
    EVIDENCE="Manual review required — see remediation"
    emit_line "$FINDING_ID" "$TITLE" "$RISK" "$STATUS" "$FIX_TYPE" "$EVIDENCE" "$REMEDIATION"
    esc_id=$(escape_html <<<"$FINDING_ID" || echo "$FINDING_ID")
    esc_title=$(escape_html <<<"$TITLE" || echo "$TITLE")
    esc_risk=$(escape_html <<<"$RISK" || echo "$RISK")
    esc_fix=$(escape_html <<<"$FIX_TYPE" || echo "$FIX_TYPE")
    esc_evd=$(escape_html <<<"$EVIDENCE" || echo "$EVIDENCE")
    esc_rem=$(escape_html <<<"$REMEDIATION" || echo "$REMEDIATION")
    echo "<tr class=\"manual\"><td>$esc_id</td><td>$esc_title</td><td>$esc_risk</td><td>$esc_fix</td><td>Manual Review</td><td><pre>$esc_evd</pre></td><td><pre>$esc_rem</pre></td></tr>" >> "$OUTHTML"
    continue
  fi

  # Check for multiple patterns (&&)
  found=false
  all_found=true
  evidence=""
  if [[ "$AUTO_REGEX" == *"&&"* ]]; then
    IFS='&&' read -ra parts <<< "$AUTO_REGEX"
    for p in "${parts[@]}"; do
      out=$(match_regex "$p")
      status_line=$(echo "$out" | head -n1)
      if [[ "$status_line" == "regex_error:"* ]]; then
        echo "Regex error for $p: ${status_line#regex_error:}" >&2
        all_found=false
        break
      fi
      snippet=$(echo "$out" | tail -n +2)
      if [[ "$status_line" != "found" ]]; then all_found=false; fi
      evidence+="$snippet\n"
    done
    if $all_found; then found=true; fi
  else
    out=$(match_regex "$AUTO_REGEX")
    status_line=$(echo "$out" | head -n1)
    if [[ "$status_line" == "regex_error:"* ]]; then
      echo "Regex error for $AUTO_REGEX: ${status_line#regex_error:}" >&2
      continue
    fi
    evidence=$(echo "$out" | tail -n +2)
    if [[ "$status_line" == "found" ]]; then found=true; fi
  fi

  # Determine PASS based on PASS_WHEN
  if [[ "$PASS_WHEN" == "contains" ]]; then
    PASS=$found
  elif [[ "$PASS_WHEN" == "not_contains" ]]; then
    PASS=$( ! $found )
  else
    echo "Invalid PASS_WHEN: $PASS_WHEN" >&2
    continue
  fi

  # Adjust evidence message
  if $PASS; then
    if $found; then
      :  # evidence is snippet (good match for contains)
    else
      evidence="No bad configuration found."
    fi
  else
    if $found; then
      :  # evidence is snippet (bad match for not_contains)
    else
      evidence="Required configuration not found."
    fi
  fi

  if $PASS; then STATUS="Pass"; else STATUS="Fail"; fi

  emit_line "$FINDING_ID" "$TITLE" "$RISK" "$STATUS" "$FIX_TYPE" "$evidence" "$REMEDIATION"

  cls="fail"
  [[ "$STATUS" == "Pass" ]] && cls="pass"
  esc_id=$(escape_html <<<"$FINDING_ID" || echo "$FINDING_ID")
  esc_title=$(escape_html <<<"$TITLE" || echo "$TITLE")
  esc_risk=$(escape_html <<<"$RISK" || echo "$RISK")
  esc_fix=$(escape_html <<<"$FIX_TYPE" || echo "$FIX_TYPE")
  esc_evd=$(escape_html <<<"$evidence" || echo "$evidence")
  esc_rem=$(escape_html <<<"$REMEDIATION" || echo "$REMEDIATION")
  echo "<tr class=\"$cls\"><td>$esc_id</td><td>$esc_title</td><td>$esc_risk</td><td>$esc_fix</td><td>$STATUS</td><td><pre>$esc_evd</pre></td><td><pre>$esc_rem</pre></td></tr>" >> "$OUTHTML"

done <<< "$CHECKS"

html_end

echo "Done. Results:"
echo " - Machine output: $OUTTXT"
echo " - HTML report:  $OUTHTML"
exit 0
