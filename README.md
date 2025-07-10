# forticis
This Bash script automates compliance checks for FortiGate firewalls running FortiOS, based on the CIS FortiGate Benchmark v1.3.0. It connects to a FortiGate device via SSH, performs automated configuration checks (including pre-login and post-login banner settings), and generates an HTML report with a pie chart, summary, and detailed findings (Finding ID, Issue Name, Risk Rating, Status, Remediation).

# Features
```
Interactive Input: Prompts for FortiGate IP address, SSH port, username, and password (password input is hidden).

Automated Checks: Evaluates 25+ CIS Benchmark recommendations, including:

2.1.1: Ensure Pre-Login Banner is set

2.1.2: Ensure Post-Login Banner is set

DNS, NTP, password policy, HA, logging, and more

Dependency Installation: Automatically installs sshpass and bc if missing (supports apt and yum package managers).

Script Banner: Displays a welcome message with script details.

User Confirmation: Requires user permission before execution.

HTML Report: Generates a report (cis_fortigate_compliance_report.html) with:

Pie chart showing pass/fail percentages

Summary of results (e.g., "20 of 25 checks passed (80%)")

Table with Finding ID, Issue Name, Risk Rating (color-coded), Status (Pass/Fail), and Remediation (CLI/GUI steps)
```
# Requirements
```
System: Linux (e.g., Ubuntu, CentOS) or Bash-compatible environment (e.g., WSL on Windows).

Privileges: sudo access for installing dependencies (sshpass, bc).

FortiGate Setup:

FortiOS 7.0.x.
SSH enabled on the FortiGate interface:

config system interface
edit <interface_name>
set allowaccess ssh https ping
end

User account with CLI access (show, diag commands).

Network connectivity to the FortiGate IP and SSH port (default: 22).

Internet Access: For Bootstrap and Chart.js CDNs in the HTML report (or host locally).
```
# Installation
```
Clone the Repository:

git clone https://github.com/3tternp/forticis.git
cd forticis

Make the Script Executable:

chmod +x check_cis_fortigate.sh

```
# Dependencies:
```
The script automatically installs sshpass and bc if missing.

Supported package managers: apt (Debian/Ubuntu), yum (CentOS/RHEL).

Manual installation (if preferred):

sudo apt-get install sshpass bc  # Debian/Ubuntu
sudo yum install sshpass bc     # CentOS/RHEL
``` 
# Usage
```
Run the Script:

./check_cis_fortigate.sh
```
# Script Flow:
```
Banner: Displays script details (title, version, features).

Permission Prompt: Asks for confirmation to proceed (y/n).

Dependency Check: Installs sshpass and bc if missing (requires sudo and user confirmation).
```
# Input Prompts:
```
FortiGate IP address (e.g., 192.168.1.1).

SSH port (default: 22).

Username (e.g., admin).

Password (hidden input).
```
