#!/bin/bash

# Digital Forensics Investigation Toolkit
# Collection of forensic scripts for incident response and investigation
# Usage: ./forensics.sh [command] [options]

set -e

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
EVIDENCE_DIR="$HOME/forensic-evidence"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$EVIDENCE_DIR/forensic-log-$TIMESTAMP.txt"

# Utility functions
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
    echo "=== $1 ===" >> "$LOG_FILE" 2>/dev/null || true
}

print_status() {
    echo -e "${GREEN}[FORENSIC]${NC} $1"
    echo "[$(date)] $1" >> "$LOG_FILE" 2>/dev/null || true
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[$(date)] WARNING: $1" >> "$LOG_FILE" 2>/dev/null || true
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date)] ERROR: $1" >> "$LOG_FILE" 2>/dev/null || true
}

print_evidence() {
    echo -e "${PURPLE}[EVIDENCE]${NC} $1"
    echo "[$(date)] EVIDENCE: $1" >> "$LOG_FILE" 2>/dev/null || true
}

# Initialize forensic environment
init_forensics() {
    if [ ! -d "$EVIDENCE_DIR" ]; then
        mkdir -p "$EVIDENCE_DIR"
        chmod 700 "$EVIDENCE_DIR"
        print_status "Created evidence directory: $EVIDENCE_DIR"
    fi
    
    # Create case structure
    mkdir -p "$EVIDENCE_DIR/$CASE_ID"/{system,network,files,logs,memory,timeline}
    
    cat > "$LOG_FILE" << EOF
DIGITAL FORENSICS INVESTIGATION LOG
===================================
Case ID: $CASE_ID
Investigation Started: $(date)
Investigator: $(whoami)
System: $(hostname)
IP Address: $(hostname -I | awk '{print $1}')

EOF
    
    print_status "Forensic investigation initialized - Case ID: $CASE_ID"
}

# System information collection
collect_system_info() {
    print_header "SYSTEM INFORMATION COLLECTION"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/system"
    
    {
        echo "=== SYSTEM OVERVIEW ==="
        echo "Hostname: $(hostname)"
        echo "Date/Time: $(date)"
        echo "Uptime: $(uptime)"
        echo "Kernel: $(uname -a)"
        echo "OS Version: $(cat /etc/os-release 2>/dev/null || echo 'Unknown')"
        echo
        
        echo "=== HARDWARE INFORMATION ==="
        echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
        echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
        echo "Architecture: $(uname -m)"
        echo
        
        echo "=== RUNNING PROCESSES ==="
        ps auxf
        echo
        
        echo "=== NETWORK CONNECTIONS ==="
        netstat -tulpn 2>/dev/null || ss -tulpn
        echo
        
        echo "=== LOADED MODULES ==="
        lsmod
        echo
        
        echo "=== ENVIRONMENT VARIABLES ==="
        env | sort
        echo
        
    } > "$output_dir/system-info.txt"
    
    # Process tree
    pstree -p > "$output_dir/process-tree.txt" 2>/dev/null || echo "pstree not available"
    
    # System calls (if available)
    if command -v strace >/dev/null 2>&1; then
        timeout 10 strace -c -p 1 > "$output_dir/syscalls.txt" 2>&1 || true
    fi
    
    print_evidence "System information collected in $output_dir"
}

# Network forensics
collect_network_evidence() {
    print_header "NETWORK EVIDENCE COLLECTION"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/network"
    
    {
        echo "=== NETWORK INTERFACES ==="
        ip addr show
        echo
        
        echo "=== ROUTING TABLE ==="
        ip route show
        echo
        
        echo "=== ARP TABLE ==="
        arp -a 2>/dev/null || ip neigh show
        echo
        
        echo "=== ACTIVE CONNECTIONS ==="
        netstat -an 2>/dev/null || ss -an
        echo
        
        echo "=== LISTENING SERVICES ==="
        netstat -tlnp 2>/dev/null || ss -tlnp
        echo
        
        echo "=== NETWORK STATISTICS ==="
        cat /proc/net/dev
        echo
        
        echo "=== DNS CONFIGURATION ==="
        cat /etc/resolv.conf 2>/dev/null || echo "DNS config not accessible"
        echo
        
        echo "=== HOSTS FILE ==="
        cat /etc/hosts 2>/dev/null || echo "Hosts file not accessible"
        echo
        
    } > "$output_dir/network-info.txt"
    
    # Capture network traffic (if tcpdump available)
    if command -v tcpdump >/dev/null 2>&1; then
        print_status "Capturing network traffic for 30 seconds..."
        timeout 30 tcpdump -w "$output_dir/network-capture.pcap" -i any 2>/dev/null || true
    fi
    
    # Firewall rules
    {
        echo "=== IPTABLES RULES ==="
        iptables -L -n -v 2>/dev/null || echo "iptables not accessible"
        echo
        
        echo "=== UFW STATUS ==="
        ufw status verbose 2>/dev/null || echo "UFW not available"
        echo
        
    } > "$output_dir/firewall-rules.txt"
    
    print_evidence "Network evidence collected in $output_dir"
}

# File system analysis
analyze_filesystem() {
    print_header "FILESYSTEM ANALYSIS"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/files"
    
    # Recently modified files
    print_status "Finding recently modified files..."
    find / -type f -mtime -7 2>/dev/null | head -1000 > "$output_dir/recent-files.txt" || true
    
    # Recently accessed files
    find / -type f -atime -1 2>/dev/null | head -1000 > "$output_dir/accessed-files.txt" || true
    
    # Large files
    find / -type f -size +100M 2>/dev/null | head -100 > "$output_dir/large-files.txt" || true
    
    # SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > "$output_dir/suid-sgid-files.txt" || true
    
    # World-writable files
    find / -type f -perm -002 2>/dev/null | head -500 > "$output_dir/world-writable.txt" || true
    
    # Hidden files in common directories
    {
        echo "=== HIDDEN FILES IN /tmp ==="
        ls -la /tmp/.*  2>/dev/null || echo "No hidden files in /tmp"
        echo
        
        echo "=== HIDDEN FILES IN /var/tmp ==="
        ls -la /var/tmp/.* 2>/dev/null || echo "No hidden files in /var/tmp"
        echo
        
        echo "=== HIDDEN FILES IN USER HOMES ==="
        find /home -name ".*" -type f 2>/dev/null | head -100 || echo "No user home access"
        echo
        
    } > "$output_dir/hidden-files.txt"
    
    # File integrity check (if available)
    if command -v debsums >/dev/null 2>&1; then
        debsums -c > "$output_dir/file-integrity.txt" 2>&1 || true
    fi
    
    # Disk usage
    {
        echo "=== DISK USAGE ==="
        df -h
        echo
        
        echo "=== DIRECTORY SIZES ==="
        du -sh /* 2>/dev/null | sort -hr | head -20
        echo
        
    } > "$output_dir/disk-usage.txt"
    
    print_evidence "Filesystem analysis completed in $output_dir"
}

# Log analysis
analyze_logs() {
    print_header "LOG ANALYSIS"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/logs"
    
    # Authentication logs
    {
        echo "=== SUCCESSFUL LOGINS ==="
        grep "Accepted" /var/log/auth.log* 2>/dev/null | tail -50 || echo "No auth logs accessible"
        echo
        
        echo "=== FAILED LOGINS ==="
        grep "Failed" /var/log/auth.log* 2>/dev/null | tail -50 || echo "No failed login logs"
        echo
        
        echo "=== SUDO USAGE ==="
        grep "sudo:" /var/log/auth.log* 2>/dev/null | tail -50 || echo "No sudo logs"
        echo
        
        echo "=== USER ADDITIONS ==="
        grep "useradd" /var/log/auth.log* 2>/dev/null || echo "No user addition logs"
        echo
        
    } > "$output_dir/auth-analysis.txt"
    
    # System logs
    {
        echo "=== SYSTEM ERRORS ==="
        journalctl -p err -n 50 --no-pager 2>/dev/null || grep -i error /var/log/syslog* 2>/dev/null | tail -50 || echo "No error logs accessible"
        echo
        
        echo "=== KERNEL MESSAGES ==="
        dmesg | tail -50 2>/dev/null || echo "dmesg not accessible"
        echo
        
        echo "=== CRON LOGS ==="
        grep -i cron /var/log/syslog* 2>/dev/null | tail -50 || echo "No cron logs"
        echo
        
    } > "$output_dir/system-logs.txt"
    
    # Web server logs (if present)
    {
        echo "=== APACHE ACCESS LOGS ==="
        tail -100 /var/log/apache2/access.log* 2>/dev/null || echo "No Apache logs"
        echo
        
        echo "=== APACHE ERROR LOGS ==="
        tail -100 /var/log/apache2/error.log* 2>/dev/null || echo "No Apache error logs"
        echo
        
        echo "=== NGINX ACCESS LOGS ==="
        tail -100 /var/log/nginx/access.log* 2>/dev/null || echo "No Nginx logs"
        echo
        
        echo "=== NGINX ERROR LOGS ==="
        tail -100 /var/log/nginx/error.log* 2>/dev/null || echo "No Nginx error logs"
        echo
        
    } > "$output_dir/web-server-logs.txt"
    
    # Security logs
    {
        echo "=== IPTABLES LOGS ==="
        grep -i iptables /var/log/kern.log* 2>/dev/null | tail -50 || echo "No iptables logs"
        echo
        
        echo "=== FAIL2BAN LOGS ==="
        grep -i fail2ban /var/log/fail2ban.log* 2>/dev/null | tail -50 || echo "No fail2ban logs"
        echo
        
    } > "$output_dir/security-logs.txt"
    
    print_evidence "Log analysis completed in $output_dir"
}

# Memory analysis
collect_memory_info() {
    print_header "MEMORY ANALYSIS"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/memory"
    
    # Memory statistics
    {
        echo "=== MEMORY USAGE ==="
        free -h
        echo
        
        echo "=== MEMORY MAP ==="
        cat /proc/meminfo
        echo
        
        echo "=== SWAP USAGE ==="
        swapon -s 2>/dev/null || echo "No swap information"
        echo
        
    } > "$output_dir/memory-stats.txt"
    
    # Process memory usage
    {
        echo "=== TOP MEMORY CONSUMERS ==="
        ps aux --sort=-%mem | head -20
        echo
        
        echo "=== MEMORY MAPS ==="
        for pid in $(ps -eo pid --no-headers | head -10); do
            if [ -r "/proc/$pid/maps" ]; then
                echo "--- Process $pid ---"
                cat "/proc/$pid/maps" 2>/dev/null | head -10
                echo
            fi
        done
        
    } > "$output_dir/process-memory.txt"
    
    # Kernel memory
    {
        echo "=== KERNEL MEMORY ==="
        cat /proc/slabinfo 2>/dev/null | head -20 || echo "Slab info not accessible"
        echo
        
        echo "=== MODULES ==="
        cat /proc/modules 2>/dev/null || echo "Module info not accessible"
        echo
        
    } > "$output_dir/kernel-memory.txt"
    
    # Memory dump (if available and permissions allow)
    if [ -r /proc/kcore ] && command -v dd >/dev/null 2>&1; then
        print_status "Creating memory sample (first 1MB)..."
        dd if=/proc/kcore of="$output_dir/memory-sample.bin" bs=1M count=1 2>/dev/null || true
    fi
    
    print_evidence "Memory analysis completed in $output_dir"
}

# Timeline generation
generate_timeline() {
    print_header "TIMELINE GENERATION"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/timeline"
    local timeline_file="$output_dir/timeline.txt"
    
    {
        echo "=== SYSTEM TIMELINE ==="
        echo "Generated: $(date)"
        echo
        
        # Boot time
        echo "$(stat -c %y /proc/1 2>/dev/null || echo 'Unknown') - System Boot"
        
        # Recent file modifications
        find /etc /var/log /tmp -type f -mtime -7 -exec stat -c "%y %n" {} \; 2>/dev/null | sort | tail -50
        
        # Authentication events
        grep -h "Accepted\|Failed" /var/log/auth.log* 2>/dev/null | \
        awk '{print $1" "$2" "$3" - "$0}' | sort | tail -50
        
        # Process start times (approximation)
        ps -eo pid,lstart,cmd --no-headers | sort -k2 | tail -50
        
    } > "$timeline_file"
    
    # Create CSV timeline for analysis tools
    {
        echo "Timestamp,Event_Type,Description"
        
        # File modifications
        find /etc /var/log /tmp -type f -mtime -7 -exec stat -c "%y,File_Modified,%n" {} \; 2>/dev/null | head -100
        
        # Authentication events
        grep -h "Accepted" /var/log/auth.log* 2>/dev/null | \
        awk -F: '{gsub(/^ +| +$/,"",$0); print $1":"$2":"$3",Login_Success,"$0}' | head -50
        
        grep -h "Failed" /var/log/auth.log* 2>/dev/null | \
        awk -F: '{gsub(/^ +| +$/,"",$0); print $1":"$2":"$3",Login_Failed,"$0}' | head -50
        
    } > "$output_dir/timeline.csv"
    
    print_evidence "Timeline generated in $output_dir"
}

# Malware detection
detect_malware() {
    print_header "MALWARE DETECTION"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/malware"
    mkdir -p "$output_dir"
    
    # Suspicious processes
    {
        echo "=== SUSPICIOUS PROCESSES ==="
        echo "Processes without parent:"
        ps -eo pid,ppid,cmd | awk '$2==0 && $1!=1 {print}'
        echo
        
        echo "Processes with suspicious names:"
        ps aux | grep -E "(nc|netcat|nmap|wget|curl|python|perl|ruby|sh|bash)" | grep -v grep
        echo
        
        echo "Processes listening on network:"
        netstat -tlnp 2>/dev/null | grep LISTEN || ss -tlnp | grep LISTEN
        echo
        
    } > "$output_dir/suspicious-processes.txt"
    
    # Suspicious files
    {
        echo "=== SUSPICIOUS FILES ==="
        echo "Recently created executables:"
        find / -type f -executable -mtime -7 2>/dev/null | head -100
        echo
        
        echo "Files in tmp directories:"
        find /tmp /var/tmp -type f 2>/dev/null | head -100
        echo
        
        echo "Hidden executables:"
        find / -type f -name ".*" -executable 2>/dev/null | head -50
        echo
        
        echo "Scripts in unusual locations:"
        find /dev /proc -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | head -50
        echo
        
    } > "$output_dir/suspicious-files.txt"
    
    # Network indicators
    {
        echo "=== NETWORK INDICATORS ==="
        echo "Unusual network connections:"
        netstat -an 2>/dev/null | grep -E "ESTABLISHED|LISTEN" | grep -v -E ":22|:80|:443|:53" || \
        ss -an | grep -E "ESTAB|LISTEN" | grep -v -E ":22|:80|:443|:53"
        echo
        
        echo "DNS queries (if available):"
        tail -50 /var/log/daemon.log* 2>/dev/null | grep -i dns || echo "No DNS logs found"
        echo
        
    } > "$output_dir/network-indicators.txt"
    
    # Hash suspicious files
    if command -v sha256sum >/dev/null 2>&1; then
        print_status "Generating file hashes..."
        find /tmp /var/tmp -type f 2>/dev/null | xargs sha256sum > "$output_dir/file-hashes.txt" 2>/dev/null || true
    fi
    
    print_evidence "Malware detection completed in $output_dir"
}

# User activity analysis
analyze_user_activity() {
    print_header "USER ACTIVITY ANALYSIS"
    
    local output_dir="$EVIDENCE_DIR/$CASE_ID/user-activity"
    
    # Command history
    {
        echo "=== COMMAND HISTORIES ==="
        for user_home in /home/*; do
            if [ -d "$user_home" ]; then
                username=$(basename "$user_home")
                echo "--- History for $username ---"
                
                # Bash history
                if [ -f "$user_home/.bash_history" ]; then
                    echo "Bash history:"
                    tail -50 "$user_home/.bash_history" 2>/dev/null || echo "No access to bash history"
                fi
                
                # Zsh history
                if [ -f "$user_home/.zsh_history" ]; then
                    echo "Zsh history:"
                    tail -50 "$user_home/.zsh_history" 2>/dev/null || echo "No access to zsh history"
                fi
                
                echo
            fi
        done
        
        # Root history
        echo "--- Root history ---"
        if [ -f "/root/.bash_history" ]; then
            tail -50 /root/.bash_history 2>/dev/null || echo "No access to root history"
        fi
        
    } > "$output_dir/command-history.txt"
    
    # Login information
    {
        echo "=== LOGIN INFORMATION ==="
        echo "Last logins:"
        last -n 50 2>/dev/null || echo "Last command not available"
        echo
        
        echo "Failed logins:"
        lastb -n 50 2>/dev/null || echo "lastb command not available"
        echo
        
        echo "Currently logged in:"
        who 2>/dev/null || w 2>/dev/null || echo "No current login info"
        echo
        
    } > "$output_dir/login-info.txt"
    
    # User files
    {
        echo "=== USER FILE ACTIVITY ==="
        for user_home in /home/*; do
            if [ -d "$user_home" ]; then
                username=$(basename "$user_home")
                echo "--- Files for $username ---"
                find "$user_home" -type f -mtime -7 2>/dev/null | head -20 || echo "No access to user files"
                echo
            fi
        done
        
    } > "$output_dir/user-files.txt"
    
    print_evidence "User activity analysis completed in $output_dir"
}

# Generate comprehensive report
generate_report() {
    print_header "GENERATING COMPREHENSIVE FORENSIC REPORT"
    
    local report_file="$EVIDENCE_DIR/$CASE_ID/FORENSIC_REPORT_$CASE_ID.txt"
    
    {
        cat << EOF
DIGITAL FORENSICS INVESTIGATION REPORT
=====================================

Case Information:
- Case ID: $CASE_ID
- Investigation Date: $(date)
- Investigator: $(whoami)
- Target System: $(hostname)
- System IP: $(hostname -I | awk '{print $1}')

EXECUTIVE SUMMARY
================
This report contains the results of a digital forensics investigation
conducted on the system $(hostname) at $(date).

INVESTIGATION METHODOLOGY
========================
The following forensic procedures were executed:
1. System information collection
2. Network evidence gathering
3. Filesystem analysis
4. Log file examination
5. Memory analysis
6. Timeline generation
7. Malware detection
8. User activity analysis

EVIDENCE LOCATIONS
=================
All collected evidence is stored in:
$EVIDENCE_DIR/$CASE_ID/

Directory Structure:
- system/          - System configuration and process information
- network/         - Network connections and traffic data
- files/           - Filesystem analysis results
- logs/            - System and application log analysis
- memory/          - Memory usage and process information
- timeline/        - Chronological event timeline
- malware/         - Malware detection results
- user-activity/   - User behavior and activity logs

KEY FINDINGS
===========

System Status:
- Hostname: $(hostname)
- OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)
- Kernel: $(uname -r)
- Uptime: $(uptime | cut -d',' -f1)
- Active Processes: $(ps aux | wc -l)
- Network Connections: $(netstat -an 2>/dev/null | wc -l || ss -an | wc -l)

Security Indicators:
- Failed Login Attempts: $(grep -c "Failed" /var/log/auth.log* 2>/dev/null || echo "0")
- SUID Files: $(find / -type f -perm -4000 2>/dev/null | wc -l)
- Listening Services: $(netstat -tln 2>/dev/null | grep LISTEN | wc -l || ss -tln | grep LISTEN | wc -l)

RECOMMENDATIONS
==============
1. Review all evidence files for suspicious activity
2. Cross-reference timeline with known incident times
3. Analyze network traffic for unusual communications
4. Verify integrity of system files
5. Check for unauthorized user accounts or privilege escalation
6. Review application logs for signs of compromise

CHAIN OF CUSTODY
===============
Evidence collected by: $(whoami)
Collection time: $(date)
Collection method: Automated forensic script
Evidence location: $EVIDENCE_DIR/$CASE_ID/
Hash verification: See individual evidence files

INVESTIGATION COMPLETED
======================
Investigation completed at: $(date)
Total evidence files: $(find "$EVIDENCE_DIR/$CASE_ID" -type f | wc -l)
Report file: $report_file

EOF
    } > "$report_file"
    
    print_evidence "Comprehensive forensic report generated: $report_file"
}

# Quick triage
quick_triage() {
    print_header "QUICK TRIAGE"
    
    print_status "Performing rapid system assessment..."
    
    echo -e "${CYAN}=== QUICK SYSTEM TRIAGE ===${NC}"
    echo "Time: $(date)"
    echo "System: $(hostname) ($(uname -r))"
    echo "Uptime: $(uptime)"
    echo
    
    echo -e "${YELLOW}Active Network Connections:${NC}"
    netstat -tan 2>/dev/null | grep ESTABLISHED | wc -l || ss -tan | grep ESTAB | wc -l
    echo
    
    echo -e "${YELLOW}Suspicious Processes:${NC}"
    ps aux | grep -E "(nc|netcat|nmap|wget.*http|curl.*http)" | grep -v grep || echo "None detected"
    echo
    
    echo -e "${YELLOW}Recent Failed Logins:${NC}"
    grep "Failed password" /var/log/auth.log* 2>/dev/null | tail -5 || echo "No recent failures"
    echo
    
    echo -e "${YELLOW}Unusual Network Activity:${NC}"
    netstat -an 2>/dev/null | grep -E "LISTEN.*:(1234|4444|5555|6666|7777|31337)" || \
    ss -an | grep -E "LISTEN.*:(1234|4444|5555|6666|7777|31337)" || echo "No suspicious ports"
    echo
    
    echo -e "${YELLOW}High CPU Processes:${NC}"
    ps aux --sort=-%cpu | head -6 | tail -5
    echo
}

# Show help
show_help() {
    cat << EOF
Digital Forensics Investigation Toolkit

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    full            Complete forensic investigation
    triage          Quick system triage
    system          Collect system information
    network         Gather network evidence
    filesystem      Analyze filesystem
    logs            Analyze system logs
    memory          Collect memory information
    timeline        Generate event timeline
    malware         Detect malware indicators
    users           Analyze user activity
    report          Generate comprehensive report
    help            Show this help message

Options:
    --case-id ID    Specify custom case ID
    --output DIR    Specify output directory

Examples:
    $0 full                    # Complete investigation
    $0 triage                  # Quick assessment
    $0 network                 # Network evidence only
    $0 malware                 # Malware detection
    $0 --case-id INCIDENT123 full

Evidence Location: $EVIDENCE_DIR

Note: Some commands require root privileges for full functionality.

EOF
}

# Main function
main() {
    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --case-id)
                CASE_ID="$2"
                shift 2
                ;;
            --output)
                EVIDENCE_DIR="$2"
                LOG_FILE="$EVIDENCE_DIR/forensic-log-$TIMESTAMP.txt"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Handle commands
    case "${1:-help}" in
        "full")
            init_forensics
            collect_system_info
            collect_network_evidence
            analyze_filesystem
            analyze_logs
            collect_memory_info
            generate_timeline
            detect_malware
            analyze_user_activity
            generate_report
            print_status "Complete forensic investigation finished - Case: $CASE_ID"
            ;;
        "triage")
            quick_triage
            ;;
        "system")
            init_forensics
            collect_system_info
            ;;
        "network")
            init_forensics
            collect_network_evidence
            ;;
        "filesystem")
            init_forensics
            analyze_filesystem
            ;;
        "logs")
            init_forensics
            analyze_logs
            ;;
        "memory")
            init_forensics
            collect_memory_info
            ;;
        "timeline")
            init_forensics
            generate_timeline
            ;;
        "malware")
            init_forensics
            detect_malware
            ;;
        "users")
            init_forensics
            analyze_user_activity
            ;;
        "report")
            init_forensics
            generate_report
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"