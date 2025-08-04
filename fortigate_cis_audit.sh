#!/bin/bash

# Display script banner
cat << 'EOF'

========================================
   CIS FortiGate Compliance Checker
========================================
Version: 1.0.0          Developer: Astra
========================================

EOF

# Prompt for user permission to proceed
echo "Do you want to proceed with the compliance check? (y/n):"
read -r confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Execution aborted by user."
    exit 0
fi

# Install dependencies
install_dependencies() {
    if ! command -v sshpass &> /dev/null; then
        echo "sshpass is not installed. Attempting to install..."
        read -p "Proceed with installation? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Error: sshpass is required. Please install manually and retry."
            exit 1
        fi
        sudo apt-get install -y sshpass || sudo yum install -y sshpass
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install sshpass. Please install manually."
            exit 1
        fi
        echo "sshpass installed successfully."
    fi
    if ! command -v bc &> /dev/null; then
        echo "bc is not installed. Attempting to install..."
        read -p "Proceed with installation? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Error: bc is required. Please install manually and retry."
            exit 1
        fi
        sudo apt-get install -y bc || sudo yum install -y bc
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install bc. Please install manually."
            exit 1
        fi
        echo "bc installed successfully."
    fi
}

# Validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Validate port
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
        return 0
    else
        return 1
    fi
}

# Install dependencies
install_dependencies

# Prompt for user input
echo "Enter FortiGate IP address:"
read -r FORTIGATE_IP
if ! validate_ip "$FORTIGATE_IP"; then
    echo "Error: Invalid IP address format."
    exit 1
fi

echo "Enter SSH port (default 22):"
read -r SSH_PORT
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
fi
if ! validate_port "$SSH_PORT"; then
    echo "Error: Invalid port number. Must be between 1 and 65535."
    exit 1
fi

echo "Enter FortiGate username (read-only profile):"
read -r USERNAME
if [ -z "$USERNAME" ]; then
    echo "Error: Username cannot be empty."
    exit 1
fi

echo "Enter FortiGate password (input will be hidden):"
read -s PASSWORD
echo
if [ -z "$PASSWORD" ]; then
    echo "Error: Password cannot be empty."
    exit 1
fi

# Set SSH command with timeout
SSH_COMMAND="sshpass -p \"$PASSWORD\" ssh -v -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=DEBUG3 -o ServerAliveInterval=15 $USERNAME@$FORTIGATE_IP"

# Test SSH connection
echo "Testing SSH connection to $FORTIGATE_IP on port $SSH_PORT..."
output=$($SSH_COMMAND "get system status; exit" 2>&1)
if echo "$output" | grep -q "Connection timed out" || echo "$output" | grep -q "Permission denied"; then
    echo "Error: Failed to connect to $FORTIGATE_IP on port $SSH_PORT. Debug output: $output"
    exit 1
fi
if ! echo "$output" | grep -q "Version"; then
    echo "Error: Failed to get system status from $FORTIGATE_IP. Debug output: $output"
    exit 1
fi
echo "SSH connection established successfully."

REPORT_FILE="cis_fortigate_compliance_report.html"
TEMP_FILE="cis_fortigate_temp.txt"

# Initialize temporary file for results
: > $TEMP_FILE

# Define findings with ID, Name, Risk, Fix Type, Expected Output, Command
declare -A FINDINGS=(
    ["1.1"]="Ensure DNS server is configured|Medium|Involved|show system dns|set primary 8.8.8.8.*set secondary 8.8.4.4"
    ["2.1.1"]="Ensure Pre-Login Banner is set|Low|Quick|show system global|set pre-login-banner enable"
    ["2.1.2"]="Ensure Post-Login-Banner is set|Low|Quick|show system global|set post-login-banner enable"
    ["2.1.4"]="Ensure correct system time is configured through NTP|High|Involved|diag sys ntp status|synchronized: yes, ntpsync: enabled"
    ["2.1.5"]="Ensure hostname is set|Low|Quick|show system global|set hostname"
    ["2.1.7"]="Disable USB Firmware and configuration installation|Medium|Quick|show system auto-install|set auto-install-config disable.*set auto-install-image disable"
    ["2.1.8"]="Disable static keys for TLS|Medium|Quick|show system global|set strong-crypto enable"
    ["2.1.9"]="Enable Global Strong Encryption|Medium|Quick|show system global|set strong-crypto enable"
    ["2.2.1"]="Ensure Password Policy is enabled|High|Involved|show system password-policy|set status enable.*set minimum-length 8.*set min-lower-case-letter 1.*set min-upper-case-letter 1.*set min-non-alphanumeric 1.*set min-number 1"
    ["2.2.2"]="Ensure administrator password retries and lockout time|High|Involved|show system global|set admin-lockout-threshold 3.*set admin-lockout-duration 900"
    ["2.3.1"]="Ensure only SNMPv3 is enabled|Medium|Involved|show system snmp sysinfo|set status enable"
    ["2.4.4"]="Ensure idle timeout is configured|Medium|Quick|show system global|set admintimeout 5"
    ["2.4.5"]="Ensure only encrypted access channels|High|Involved|show system interface|set allowaccess.*ssh https ping snmp"
    ["2.5.1"]="Ensure High Availability configuration is enabled|Medium|Planned|show system ha|set mode a-p"
    ["2.5.2"]="Ensure Monitor Interfaces for HA is enabled|Medium|Planned|show system ha|set monitor"
    ["3.2"]="Ensure policies do not use ALL as Service|High|Involved|show firewall policy|set service \"FTP\" \"SNMP\""
    ["4.2.1"]="Ensure Antivirus Definition Push Updates|Medium|Quick|show system autoupdate schedule|set status enable.*set frequency automatic"
    ["4.2.3"]="Enable Outbreak Prevention Database|Medium|Quick|show antivirus profile|set fortiguard-outbreak-prevention enable"
    ["4.2.4"]="Enable AI/heuristic based malware detection|Medium|Quick|show antivirus settings|set machine-learning-detection enable"
    ["4.2.5"]="Enable grayware detection on antivirus|Medium|Quick|show antivirus settings|set grayware enable"
    ["4.3.1"]="Enable Botnet C&C Domain Blocking DNS Filter|Medium|Quick|show dnsfilter profile|set block-botnet enable"
    ["4.4.2"]="Block applications on non-default ports|Medium|Quick|show application list|set enforce-default-app-port enable"
    ["5.1.1"]="Ensure Compromised Host Quarantine|High|Involved|show system automation-action|set action-type quarantine"
    ["5.2.1.1"]="Ensure Security Fabric is Configured|Medium|Involved|show system csf|set status enable.*set group-name"
    ["7.1.1"]="Ensure Event Logging|Medium|Quick|show log eventfilter|set event enable"
    ["7.2.1"]="Encrypt Log Transmission to FortiAnalyzer/FortiManager|High|Involved|show log fortianalyzer setting|set reliable enable.*set enc-algorithm high"
    ["7.3.1"]="Centralized Logging and Reporting|Medium|Involved|show log fortianalyzer setting|set status enable"
)

# Function to execute command and check output
check_config() {
    local check_id=$1
    local description=$2
    local risk=$3
    local fix_type=$4
    local command=$5
    local expected=$6
    local remediation

    case $check_id in
        "1.1") remediation="config system dns\nset primary 8.8.8.8\nset secondary 8.8.4.4\nend\nGUI: Network > DNS, set Primary DNS Server to 8.8.8.8, Secondary to 8.8.4.4" ;;
        "2.1.1") remediation="config system global\nset pre-login-banner enable\nend\nGUI: System > Replacement Messages > Extended View > Pre-login Disclaimer Message, enable and configure message" ;;
        "2.1.2") remediation="config system global\nset post-login-banner enable\nend\nGUI: System > Replacement Messages > Extended View > Post-login Disclaimer Message, enable and configure message" ;;
        "2.1.4") remediation="config system ntp\nset ntpsync enable\nset server \"ntp2.fortiguard.com\"\nend\nGUI: System > Network > NTP" ;;
        "2.1.5") remediation="config system global\nset hostname <desired_hostname>\nend\nGUI: System > Settings > Hostname" ;;
        "2.1.7") remediation="config system auto-install\nset auto-install-config disable\nset auto-install-image disable\nend\nGUI: System > System > Auto Install" ;;
        "2.1.8") remediation="config system global\nset strong-crypto enable\nend\nGUI: System > Settings > Advanced Settings" ;;
        "2.1.9") remediation="config system global\nset strong-crypto enable\nend\nGUI: System > Settings > Advanced Settings" ;;
        "2.2.1") remediation="config system password-policy\nset status enable\nset apply-to admin-password ipsec-preshared-key\nset minimum-length 8\nset min-lower-case-letter 1\nset min-upper-case-letter 1\nset min-non-alphanumeric 1\nset min-number 1\nend\nGUI: System > Settings > Password Policy" ;;
        "2.2.2") remediation="config system global\nset admin-lockout-threshold 3\nset admin-lockout-duration 900\nend\nGUI: System > Settings > Administration Settings" ;;
        "2.3.1") remediation="config system snmp sysinfo\nset status enable\nend\nconfig system snmp community\ndelete public\nend\nconfig system snmp user\nedit \"snmp_test\"\nset security-level auth-priv\nset auth-proto sha256\nend\nGUI: System > SNMP" ;;
        "2.4.4") remediation="config system global\nset admintimeout 5\nend\nGUI: System > Settings > Administration Settings > Idle timeout" ;;
        "2.4.5") remediation="config system interface\nedit port1\nset allowaccess ssh https ping snmp\nend\nGUI: Network > Interfaces > Edit interface" ;;
        "2.5.1") remediation="config system ha\nset group-name \"FGT-HA\"\nset mode a-p\nset password <password>\nset hbdev \"port10\" 50\nend\nGUI: System > HA" ;;
        "2.5.2") remediation="config system ha\nset monitor \"port6\" \"port7\"\nend\nGUI: System > HA > Monitor Interfaces" ;;
        "3.2") remediation="config firewall policy\nedit 2\nset service \"FTP\" \"SNMP\"\nend\nGUI: Policy & Objects > Firewall Policy > Edit > Service" ;;
        "4.2.1") remediation="config system autoupdate schedule\nset status enable\nset frequency automatic\nend\nGUI: System > FortiGuard Updates" ;;
        "4.2.3") remediation="config antivirus profile\nedit <profile>\nset fortiguard-outbreak-prevention enable\nend\nGUI: Security Profiles > Antivirus > Edit Profile" ;;
        "4.2.4") remediation="config antivirus settings\nset machine-learning-detection enable\nend\nGUI: Security Profiles > Antivirus > Settings" ;;
        "4.2.5") remediation="config antivirus settings\nset grayware enable\nend\nGUI: Security Profiles > Antivirus > Settings" ;;
        "4.3.1") remediation="config dnsfilter profile\nedit <profile>\nset block-botnet enable\nend\nGUI: Security Profiles > DNS Filter > Edit Profile" ;;
        "4.4.2") remediation="config application list\nedit <profile>\nset enforce-default-app-port enable\nend\nGUI: Security Profiles > Application Control > Edit Profile" ;;
        "5.1.1") remediation="config system automation-action\nedit \"Quarantine on Fortiswitch + FortiAP\"\nset action-type quarantine\nend\nGUI: Security Fabric > Automation" ;;
        "5.2.1.1") remediation="config system csf\nset status enable\nset group-name <fabric_name>\nend\nGUI: Security Fabric > Settings" ;;
        "7.1.1") remediation="config log eventfilter\nset event enable\nend\nGUI: Log & Report > Log Settings" ;;
        "7.2.1") remediation="config log fortianalyzer setting\nset reliable enable\nset enc-algorithm high\nend\nGUI: Log & Report > Log Settings > FortiAnalyzer" ;;
        "7.3.1") remediation="config log fortianalyzer setting\nset status enable\nend\nGUI: Log & Report > Log Settings > FortiAnalyzer" ;;
    esac

    echo "Checking $check_id: $description..."
    output=$(timeout 30 $SSH_COMMAND "$command; exit" 2>&1 | grep -v "spawn" | tail -n +2)
    if [ $? -eq 124 ]; then
        echo "Error: Command for $check_id timed out on $FORTIGATE_IP."
        exit 1
    elif [ $? -ne 0 ]; then
        echo "Error: Failed to execute command for $check_id on $FORTIGATE_IP."
        exit 1
    fi
    if echo "$output" | grep -q "$expected"; then
        status="PASS"
    else
        status="FAIL"
    fi
    echo "[$status]|$check_id|$description|$risk|$fix_type|$remediation" >> $TEMP_FILE
}

# Perform compliance checks
for check in "${!FINDINGS[@]}"; do
    IFS='|' read -r description risk fix_type command expected <<< "${FINDINGS[$check]}"
    check_config "$check" "$description" "$risk" "$fix_type" "$command" "$expected"
done

# Calculate pass/fail counts
pass_count=0
total_checks=0
while IFS='|' read -r status id name risk fix_type remediation; do
    if [ "$status" = "[PASS]" ]; then
        ((pass_count++))
    fi
    ((total_checks++))
done < $TEMP_FILE

fail_count=$((total_checks - pass_count))
pass_percentage=$(bc <<< "scale=2; ($pass_count / $total_checks) * 100")
fail_percentage=$(bc <<< "scale=2; ($fail_count / $total_checks) * 100")

# Generate HTML report
cat << EOF > $REPORT_FILE
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS FortiGate Compliance Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body { padding: 20px; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .status-pass { color: #28a745; }
        .status-fail { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">CIS FortiGate 7.0.x Benchmark Compliance Report</h1>
        <p class="text-center">Generated on: $(date '+%Y-%m-%d %H:%M:%S %Z')</p>
        <hr>

        <!-- Pie Chart -->
        <div class="row mb-4">
            <div class="col-md-6 offset-md-3">
                <canvas id="complianceChart"></canvas>
            </div>
        </div>

        <!-- Summary -->
        <div class="alert alert-info">
            <strong>Summary:</strong> $pass_count of $total_checks checks passed ($pass_percentage%).
        </div>

        <!-- Findings Table -->
        <table class="table table-striped table-bordered">
            <thead class="table-dark">
                <tr>
                    <th>Finding ID</th>
                    <th>Issue Name</th>
                    <th>Risk Rating</th>
                    <th>Status</th>
                    <th>Fix Type</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
EOF

# Add table rows
while IFS='|' read -r status id name risk fix_type remediation; do
    status_clean=${status:1:-1}
    risk_class=$(echo "$risk" | tr '[:upper:]' '[:lower:]')
    cat << EOF >> $REPORT_FILE
                <tr>
                    <td>$id</td>
                    <td>$name</td>
                    <td class="risk-$risk_class">$risk</td>
                    <td class="status-$status_clean">$status_clean</td>
                    <td>$fix_type</td>
                    <td><pre>$remediation</pre></td>
                </tr>
EOF
done < $TEMP_FILE

# Complete HTML
cat << EOF >> $REPORT_FILE
            </tbody>
        </table>
    </div>

    <script>
        const ctx = document.getElementById('complianceChart').getContext('2d');
        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Passed', 'Failed'],
                datasets: [{
                    data: [$pass_percentage, $fail_percentage],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderColor: ['#fff', '#fff'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Compliance Status' }
                }
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Clean up
rm -f $TEMP_FILE

echo "Compliance check completed. HTML report saved to $REPORT_FILE"
echo "Open $REPORT_FILE in a web browser to view the report."
``````bash
#!/bin/bash

# Display script banner
cat << 'EOF'

========================================
   CIS FortiGate 7.0.x Compliance Checker
========================================
Version: 1.0.0          Developer: Astra
========================================

EOF

# Prompt for user permission to proceed
echo "Do you want to proceed with the compliance check? (y/n):"
read -r confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Execution aborted by user."
    exit 0
fi

# Function to detect package manager and install dependencies
install_dependencies() {
    local pkg_manager=""
    local install_cmd=""

    if command -v apt-get &> /dev/null; then
        pkg_manager="apt"
        install_cmd="sudo apt-get install -y"
    elif command -v yum &> /dev/null; then
        pkg_manager="yum"
        install_cmd="sudo yum install -y"
    else
        echo "Error: No supported package manager (apt or yum) found."
        exit 1
    fi

    if ! command -v sshpass &> /dev/null; then
        echo "sshpass is not installed. Attempting to install using $pkg_manager..."
        read -p "Proceed with installation? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Error: sshpass is required. Please install manually and retry."
            exit 1
        fi
        $install_cmd sshpass
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install sshpass. Please install manually."
            exit 1
        fi
        echo "sshpass installed successfully."
    fi

    if ! command -v bc &> /dev/null; then
        echo "bc is not installed. Attempting to install using $pkg_manager..."
        read -p "Proceed with installation? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Error: bc is required. Please install manually and retry."
            exit 1
        fi
        $install_cmd bc
        if [ $? -ne 0 ]; then
            echo "Error: Failed to install bc. Please install manually."
            exit 1
        fi
        echo "bc installed successfully."
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to validate port
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
        return 0
    else
        return 1
    fi
}

# Install dependencies
install_dependencies

# Prompt for user input
echo "Enter FortiGate IP address:"
read -r FORTIGATE_IP
if ! validate_ip "$FORTIGATE_IP"; then
    echo "Error: Invalid IP address format."
    exit 1
fi

echo "Enter SSH port (default 22):"
read -r SSH_PORT
if [ -z "$SSH_PORT" ]; then
    SSH_PORT=22
fi
if ! validate_port "$SSH_PORT"; then
    echo "Error: Invalid port number. Must be between 1 and 65535."
    exit 1
fi

echo "Enter FortiGate read-only username:"
read -r USERNAME
if [ -z "$USERNAME" ]; then
    echo "Error: Username cannot be empty."
    exit 1
fi

echo "Enter FortiGate password (input will be hidden):"
read -s PASSWORD
echo
if [ -z "$PASSWORD" ]; then
    echo "Error: Password cannot be empty."
    exit 1
fi

# Set SSH command with timeout and proper termination
SSH_COMMAND="sshpass -v -p \"$PASSWORD\" ssh -v -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=DEBUG3 -o ServerAliveInterval=15 $USERNAME@$FORTIGATE_IP"

# Test SSH connection with a FortiGate-compatible command
echo "Testing SSH connection to $FORTIGATE_IP on port $SSH_PORT..."
output=$($SSH_COMMAND "get system status; exit" 2>&1)
if echo "$output" | grep -q "Connection timed out" || echo "$output" | grep -q "Permission denied"; then
    echo "Error: Failed to connect to $FORTIGATE_IP on port $SSH_PORT. Debug output: $output"
    exit 1
fi
if ! echo "$output" | grep -q "Version"; then
    echo "Error: Failed to get system status from $FORTIGATE_IP. Debug output: $output"
    exit 1
fi
echo "SSH connection established successfully."

REPORT_FILE="cis_fortigate_compliance_report.html"
TEMP_FILE="cis_fortigate_temp.txt"

# Initialize temporary file for results
: > $TEMP_FILE

# Define findings information (ID, Name, Risk Rating, Fix Type, Remediation)
declare -A FINDINGS_INFO=(
    ["1.1"]="Ensure DNS server is configured|Medium|Automated|config system dns\nset primary 8.8.8.8\nset secondary 8.8.4.4\nend\nGUI: Network > DNS, set Primary DNS Server to 8.8.8.8, Secondary to 8.8.4.4"
    ["2.1.1"]="Ensure Pre-Login Banner is set|Low|Automated|config system global\nset pre-login-banner enable\nend\nGUI: System > Replacement Messages > Extended View > Pre-login Disclaimer Message, enable and configure message"
    ["2.1.2"]="Ensure Post-Login-Banner is set|Low|Automated|config system global\nset post-login-banner enable\nend\nGUI: System > Replacement Messages > Extended View > Post-login Disclaimer Message, enable and configure message"
    ["2.1.4"]="Ensure correct system time is configured through NTP|High|Automated|config system ntp\nset ntpsync enable\nset server \"ntp2.fortiguard.com\"\nend\nGUI: System > Network > NTP, enable and set server to ntp2.fortiguard.com"
    ["2.1.5"]="Ensure hostname is set|Low|Automated|config system global\nset hostname <desired_hostname>\nend\nGUI: System > Settings, set Hostname"
    ["2.1.7"]="Disable USB Firmware and configuration installation|Medium|Automated|config system auto-install\nset auto-install-config disable\nset auto-install-image disable\nend\nGUI: System > Advanced > Auto Install, disable both options"
    ["2.1.8"]="Disable static keys for TLS|Medium|Automated|config system global\nset strong-crypto enable\nend\nGUI: System > Settings, enable Strong Crypto"
    ["2.1.9"]="Enable Global Strong Encryption|Medium|Automated|config system global\nset strong-crypto enable\nend\nGUI: System > Settings, enable Strong Crypto"
    ["2.2.1"]="Ensure Password Policy is enabled|High|Automated|config system password-policy\nset status enable\nset apply-to admin-password ipsec-preshared-key\nset minimum-length 8\nset min-lower-case-letter 1\nset min-upper-case-letter 1\nset min-non-alphanumeric 1\nset min-number 1\nend\nGUI: System > Settings > Password Policy, enable and configure"
    ["2.2.2"]="Ensure administrator password retries and lockout time|High|Automated|config system global\nset admin-lockout-threshold 3\nset admin-lockout-duration 900\nend\nGUI: System > Settings, set Lockout Threshold to 3 and Duration to 900"
    ["2.3.1"]="Ensure only SNMPv3 is enabled|Medium|Automated|config system snmp sysinfo\nset status enable\nend\nconfig system snmp community\ndelete public\nend\nconfig system snmp user\nedit \"snmp_test\"\nset security-level auth-priv\nset auth-proto sha256\nend\nGUI: System > SNMP, enable v3 and remove v1/v2c communities"
    ["2.4.4"]="Ensure idle timeout is configured|Medium|Automated|config system global\nset admintimeout 5\nend\nGUI: System > Settings > Administration Settings, set Idle timeout to 5"
    ["2.4.5"]="Ensure only encrypted access channels|High|Automated|config system interface\nedit port1\nset allowaccess ssh https ping snmp\nend\nGUI: Network > Interfaces > Edit interface, allow only SSH, HTTPS, Ping, SNMP"
    ["2.5.1"]="Ensure High Availability is enabled|Medium|Automated|config system ha\nset group-name \"FGT-HA\"\nset mode a-p\nset password <password>\nset hbdev \"port10\" 50\nend\nGUI: System > HA, configure Active-Passive HA"
    ["2.5.2"]="Ensure Monitor Interfaces for HA is enabled|Medium|Automated|config system ha\nset monitor \"port6\" \"port7\"\nend\nGUI: System > HA > Monitor Interfaces, enable monitoring"
    ["3.2"]="Ensure policies do not use ALL as Service|High|Automated|config firewall policy\nedit 2\nset service \"FTP\" \"SNMP\"\nend\nGUI: Policy & Objects > Firewall Policy > Edit > Service, set specific services"
    ["4.2.1"]="Ensure Antivirus Definition Push Updates|Medium|Automated|config system autoupdate schedule\nset status enable\nset frequency automatic\nend\nGUI: System > FortiGuard Updates, set to Automatic"
    ["4.2.3"]="Enable Outbreak Prevention Database|Medium|Automated|config antivirus profile\nedit <profile>\nset fortiguard-outbreak-prevention enable\nend\nGUI: Security Profiles > Antivirus > Edit Profile, enable Outbreak Prevention"
    ["4.2.4"]="Enable AI/heuristic based malware detection|Medium|Automated|config antivirus settings\nset machine-learning-detection enable\nend\nGUI: Security Profiles > Antivirus > Settings, enable AI Detection"
    ["4.2.5"]="Enable grayware detection on antivirus|Medium|Automated|config antivirus settings\nset grayware enable\nend\nGUI: Security Profiles > Antivirus > Settings, enable Grayware Detection"
    ["4.3.1"]="Enable Botnet C&C Domain Blocking DNS Filter|Medium|Automated|config dnsfilter profile\nedit <profile>\nset block-botnet enable\nend\nGUI: Security Profiles > DNS Filter > Edit Profile, enable Botnet Blocking"
    ["4.4.2"]="Block applications on non-default ports|Medium|Automated|config application list\nedit <profile>\nset enforce-default-app-port enable\nend\nGUI: Security Profiles > Application Control > Edit Profile, enable Port Enforcement"
    ["5.1.1"]="Ensure Compromised Host Quarantine|High|Automated|config system automation-action\nedit \"Quarantine on Fortiswitch + FortiAP\"\nset action-type quarantine\nend\nGUI: Security Fabric > Automation, enable Quarantine"
    ["5.2.1.1"]="Ensure Security Fabric is Configured|Medium|Automated|config system csf\nset status enable\nset group-name <fabric_name>\nend\nGUI: Security Fabric > Settings, enable and configure Fabric"
    ["7.1.1"]="Ensure Event Logging|Medium|Automated|config log eventfilter\nset event enable\nend\nGUI: Log & Report > Log Settings, enable Event Logging"
    ["7.2.1"]="Encrypt Log Transmission to FortiAnalyzer/FortiManager|High|Automated|config log fortianalyzer setting\nset reliable enable\nset enc-algorithm high\nend\nGUI: Log & Report > Log Settings > FortiAnalyzer, enable encryption"
    ["7.3.1"]="Centralized Logging and Reporting|Medium|Automated|config log fortianalyzer setting\nset status enable\nend\nGUI: Log & Report > Log Settings > FortiAnalyzer, enable logging"
)

# Function to execute command and check output with timeout
check_config() {
    local check_id=$1
    local description=$2
    local command=$3
    local expected=$4
    local output
    local status
    local risk
    local fix_type
    local remediation

    IFS='|' read -r name risk fix_type remediation <<< "${FINDINGS_INFO[$check_id]}"

    echo "Checking $check_id: $description..."
    output=$(timeout 30 $SSH_COMMAND "$command; exit" 2>&1 | grep -v "spawn" | tail -n +2)
    if [ $? -eq 124 ]; then
        echo "Error: Command for $check_id timed out on $FORTIGATE_IP. Debug output: $output"
        exit 1
    elif [ $? -ne 0 ]; then
        echo "Error: Failed to execute command for $check_id on $FORTIGATE_IP. Debug output: $output"
        exit 1
    fi
    if echo "$output" | grep -q "$expected"; then
        status="PASS"
    else
        status="FAIL"
    fi
    echo "[$status] $check_id|$name|$risk|$fix_type|$remediation" >> $TEMP_FILE
}

# Perform compliance checks
check_config "1.1" "Ensure DNS server is configured" \
    "show system dns" \
    "set primary 8.8.8.8.*set secondary 8.8.4.4"
check_config "2.1.1" "Ensure Pre-Login Banner is set" \
    "show system global" \
    "set pre-login-banner enable"
check_config "2.1.2" "Ensure Post-Login-Banner is set" \
    "show system global" \
    "set post-login-banner enable"
check_config "2.1.4" "Ensure correct system time is configured through NTP" \
    "diag sys ntp status" \
    "synchronized: yes, ntpsync: enabled"
check_config "2.1.5" "Ensure hostname is set" \
    "show system global" \
    "set hostname"
check_config "2.1.7" "Disable USB Firmware and configuration installation" \
    "show system auto-install" \
    "set auto-install-config disable.*set auto-install-image disable"
check_config "2.1.8" "Disable static keys for TLS" \
    "show system global" \
    "set strong-crypto enable"
check_config "2.1.9" "Enable Global Strong Encryption" \
    "show system global" \
    "set strong-crypto enable"
check_config "2.2.1" "Ensure Password Policy is enabled" \
    "show system password-policy" \
    "set status enable.*set minimum-length 8.*set min-lower-case-letter 1.*set min-upper-case-letter 1.*set min-non-alphanumeric 1.*set min-number 1"
check_config "2.2.2" "Ensure administrator password retries and lockout time" \
    "show system global" \
    "set admin-lockout-threshold 3.*set admin-lockout-duration 900"
check_config "2.3.1" "Ensure only SNMPv3 is enabled" \
    "show system snmp sysinfo" \
    "set status enable"
check_config "2.3.1" "Ensure SNMPv1/v2c communities are disabled" \
    "show system snmp community" \
    "^$"
check_config "2.4.4" "Ensure idle timeout is configured" \
    "show system global" \
    "set admintimeout 5"
check_config "2.4.5" "Ensure only encrypted access channels" \
    "show system interface" \
    "set allowaccess.*ssh https ping snmp"
check_config "2.5.1" "Ensure High Availability is enabled" \
    "show system ha" \
    "set mode a-p"
check_config "2.5.2" "Ensure Monitor Interfaces for HA is enabled" \
    "show system ha" \
    "set monitor"
check_config "3.2" "Ensure policies do not use ALL as Service" \
    "show firewall policy" \
    "set service \"FTP\" \"SNMP\""
check_config "4.2.1" "Ensure Antivirus Definition Push Updates" \
    "show system autoupdate schedule" \
    "set status enable.*set frequency automatic"
check_config "4.2.3" "Enable Outbreak Prevention Database" \
    "show antivirus profile" \
    "set fortiguard-outbreak-prevention enable"
check_config "4.2.4" "Enable AI/heuristic based malware detection" \
    "show antivirus settings" \
    "set machine-learning-detection enable"
check_config "4.2.5" "Enable grayware detection on antivirus" \
    "show antivirus settings" \
    "set grayware enable"
check_config "4.3.1" "Enable Botnet C&C Domain Blocking DNS Filter" \
    "show dnsfilter profile" \
    "set block-botnet enable"
check_config "4.4.2" "Block applications on non-default ports" \
    "show application list" \
    "set enforce-default-app-port enable"
check_config "5.1.1" "Ensure Compromised Host Quarantine" \
    "show system automation-action" \
    "set action-type quarantine"
check_config "5.2.1.1" "Ensure Security Fabric is Configured" \
    "show system csf" \
    "set status enable.*set group-name"
check_config "7.1.1" "Ensure Event Logging" \
    "show log eventfilter" \
    "set event enable"
check_config "7.2.1" "Encrypt Log Transmission to FortiAnalyzer/FortiManager" \
    "show log fortianalyzer setting" \
    "set reliable enable.*set enc-algorithm high"
check_config "7.3.1" "Centralized Logging and Reporting" \
    "show log fortianalyzer setting" \
    "set status enable"

# Calculate pass/fail counts
pass_count=0
total_checks=0
while IFS='|' read -r status id name risk fix_type remediation; do
    if [ "$status" = "[PASS]" ]; then
        ((pass_count++))
    fi
    ((total_checks++))
done < $TEMP_FILE

fail_count=$((total_checks - pass_count))
pass_percentage=$(bc <<< "scale=2; ($pass_count / $total_checks) * 100")
fail_percentage=$(bc <<< "scale=2; ($fail_count / $total_checks) * 100")

# Generate HTML report
cat << EOF > $REPORT_FILE
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS FortiGate 7.0.x Compliance Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body { padding: 20px; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 5px; white-space: pre-wrap; }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .status-pass { color: #28a745; }
        .status-fail { color: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center mb-4">CIS FortiGate 7.0.x Benchmark Compliance Report</h1>
        <p class="text-center">Generated on: $(date '+%Y-%m-%d %H:%M:%S %Z')</p>
        <hr>

        <!-- Pie Chart -->
        <div class="row mb-4">
            <div class="col-md-6 offset-md-3">
                <canvas id="complianceChart"></canvas>
            </div>
        </div>

        <!-- Summary -->
        <div class="alert alert-info">
            <strong>Summary:</strong> $pass_count of $total_checks checks passed ($pass_percentage%).
        </div>

        <!-- Findings Table -->
        <table class="table table-striped table-bordered">
            <thead class="table-dark">
                <tr>
                    <th>Finding ID</th>
                    <th>Issue Name</th>
                    <th>Risk Rating</th>
                    <th>Status</th>
                    <th>Fix Type</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
EOF

# Add table rows
while IFS='|' read -r status id name risk fix_type remediation; do
    status_clean=${status:1:-1} # Remove [ ]
    risk_class=$(echo "$risk" | tr '[:upper:]' '[:lower:]')
    cat << EOF >> $REPORT_FILE
                <tr>
                    <td>$id</td>
                    <td>$name</td>
                    <td class="risk-$risk_class">$risk</td>
                    <td class="status-$status_clean">$status_clean</td>
                    <td>$fix_type</td>
                    <td><pre>$remediation</pre></td>
                </tr>
EOF
done < $TEMP_FILE

# Complete HTML
cat << EOF >> $REPORT_FILE
            </tbody>
        </table>
    </div>

    <script>
        const ctx = document.getElementById('complianceChart').getContext('2d');
        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Passed', 'Failed'],
                datasets: [{
                    data: [$pass_percentage, $fail_percentage],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderColor: ['#fff', '#fff'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Compliance Status' }
                }
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Clean up
rm -f $TEMP_FILE

echo "Compliance check completed. HTML report saved to $REPORT_FILE"
echo "Open $REPORT_FILE in a web browser to view the report."
