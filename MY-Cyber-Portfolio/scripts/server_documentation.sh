#!/bin/bash

# Server Documentation and Monitoring Script for Ubuntu
# Captures hardware, software, services, logs, and IP information
# Usage: ./server-doc.sh [command] [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
DOC_DIR="$HOME/server-docs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$DOC_DIR/server-report-$TIMESTAMP.txt"

# Utility functions
print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
    echo "=== $1 ===" >> "$REPORT_FILE" 2>/dev/null || true
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create documentation directory
create_doc_dir() {
    if [ ! -d "$DOC_DIR" ]; then
        mkdir -p "$DOC_DIR"
        chmod 755 "$DOC_DIR"
        print_status "Created documentation directory: $DOC_DIR"
    fi
}

# Initialize report file
init_report() {
    create_doc_dir
    cat > "$REPORT_FILE" << EOF
SERVER DOCUMENTATION REPORT
Generated on: $(date)
Hostname: $(hostname)
User: $(whoami)

EOF
    print_status "Report initialized: $REPORT_FILE"
}

# Document hardware information
document_hardware() {
    print_header "HARDWARE INFORMATION"
    
    {
        echo "=== SYSTEM OVERVIEW ==="
        echo "Hostname: $(hostname)"
        echo "Uptime: $(uptime)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo
        
        echo "=== CPU INFORMATION ==="
        echo "CPU Model: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
        echo "Cores: $(nproc)"
        echo "Threads: $(lscpu | grep '^CPU(s):' | awk '{print $2}')"
        echo "Architecture: $(lscpu | grep 'Architecture' | cut -d':' -f2 | xargs)"
        echo "CPU MHz: $(lscpu | grep 'CPU MHz' | cut -d':' -f2 | xargs)"
        echo
        
        echo "=== MEMORY INFORMATION ==="
        free -h
        echo
        echo "Memory Details:"
        cat /proc/meminfo | grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree)'
        echo
        
        echo "=== DISK INFORMATION ==="
        echo "Disk Usage:"
        df -h
        echo
        echo "Block Devices:"
        lsblk
        echo
        echo "Disk Details:"
        if command -v lshw >/dev/null 2>&1; then
            sudo lshw -class disk -short 2>/dev/null || echo "lshw not available"
        else
            fdisk -l 2>/dev/null | grep -E '^Disk /dev/' || echo "fdisk info not accessible"
        fi
        echo
        
        echo "=== NETWORK HARDWARE ==="
        echo "Network Interfaces:"
        ip link show
        echo
        if command -v lshw >/dev/null 2>&1; then
            echo "Network Hardware Details:"
            sudo lshw -class network -short 2>/dev/null || echo "Network hardware info not available"
        fi
        echo
        
        echo "=== PCI DEVICES ==="
        lspci 2>/dev/null || echo "PCI information not available"
        echo
        
        echo "=== USB DEVICES ==="
        lsusb 2>/dev/null || echo "USB information not available"
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Document software information
document_software() {
    print_header "SOFTWARE INFORMATION"
    
    {
        echo "=== OPERATING SYSTEM ==="
        cat /etc/os-release 2>/dev/null || echo "OS release info not available"
        echo
        
        echo "=== INSTALLED PACKAGES (APT) ==="
        echo "Total packages: $(dpkg -l | grep -c '^ii')"
        echo "Recently installed (last 30 days):"
        find /var/log/apt -name "*.log" -mtime -30 -exec grep -h "install" {} \; 2>/dev/null | tail -20 || echo "No recent installation logs"
        echo
        
        echo "=== SNAP PACKAGES ==="
        if command -v snap >/dev/null 2>&1; then
            snap list 2>/dev/null || echo "No snap packages installed"
        else
            echo "Snap not installed"
        fi
        echo
        
        echo "=== DOCKER INFORMATION ==="
        if command -v docker >/dev/null 2>&1; then
            docker --version
            echo "Docker Images:"
            docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}" 2>/dev/null || echo "Docker not accessible"
            echo
            echo "Docker Containers:"
            docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}" 2>/dev/null || echo "Docker containers not accessible"
        else
            echo "Docker not installed"
        fi
        echo
        
        echo "=== PYTHON PACKAGES ==="
        if command -v pip3 >/dev/null 2>&1; then
            echo "Python3 packages:"
            pip3 list 2>/dev/null | head -20
        else
            echo "pip3 not available"
        fi
        echo
        
        echo "=== NODE.JS PACKAGES ==="
        if command -v npm >/dev/null 2>&1; then
            echo "Node.js version: $(node --version 2>/dev/null || echo 'Not installed')"
            echo "NPM version: $(npm --version 2>/dev/null || echo 'Not installed')"
            echo "Global packages:"
            npm list -g --depth=0 2>/dev/null | head -20 || echo "NPM packages not accessible"
        else
            echo "Node.js/NPM not installed"
        fi
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Document services
document_services() {
    print_header "SERVICES INFORMATION"
    
    {
        echo "=== SYSTEMD SERVICES ==="
        echo "Active services:"
        systemctl list-units --type=service --state=active --no-pager | head -20
        echo
        echo "Failed services:"
        systemctl list-units --type=service --state=failed --no-pager || echo "No failed services"
        echo
        echo "Enabled services:"
        systemctl list-unit-files --type=service --state=enabled --no-pager | head -20
        echo
        
        echo "=== LISTENING PORTS ==="
        echo "TCP Ports:"
        ss -tlnp | head -20
        echo
        echo "UDP Ports:"
        ss -ulnp | head -10
        echo
        
        echo "=== CRON JOBS ==="
        echo "Root crontab:"
        sudo crontab -l 2>/dev/null || echo "No root crontab"
        echo
        echo "User crontabs:"
        for user in $(cut -f1 -d: /etc/passwd); do
            if sudo crontab -u "$user" -l 2>/dev/null; then
                echo "Crontab for $user:"
                sudo crontab -u "$user" -l 2>/dev/null
                echo
            fi
        done
        echo
        
        echo "=== SYSTEM TIMERS ==="
        systemctl list-timers --no-pager | head -10
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Document network and IP information
document_network() {
    print_header "NETWORK & IP INFORMATION"
    
    {
        echo "=== NETWORK INTERFACES ==="
        ip addr show
        echo
        
        echo "=== ROUTING TABLE ==="
        ip route show
        echo
        
        echo "=== DNS CONFIGURATION ==="
        cat /etc/resolv.conf 2>/dev/null || echo "DNS config not accessible"
        echo
        
        echo "=== NETWORK CONNECTIONS ==="
        echo "Active connections:"
        ss -tuln | head -20
        echo
        
        echo "=== FIREWALL STATUS ==="
        if command -v ufw >/dev/null 2>&1; then
            echo "UFW Status:"
            sudo ufw status verbose 2>/dev/null || echo "UFW status not accessible"
        fi
        echo
        if command -v iptables >/dev/null 2>&1; then
            echo "IPTables rules:"
            sudo iptables -L -n 2>/dev/null | head -20 || echo "IPTables not accessible"
        fi
        echo
        
        echo "=== EXTERNAL IP ==="
        echo "Public IP: $(curl -s ipinfo.io/ip 2>/dev/null || echo 'Not available')"
        echo "Location: $(curl -s ipinfo.io/city 2>/dev/null || echo 'Not available'), $(curl -s ipinfo.io/country 2>/dev/null || echo 'Not available')"
        echo
        
        echo "=== NETWORK STATISTICS ==="
        cat /proc/net/dev | head -10
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Document logs
document_logs() {
    print_header "SYSTEM LOGS"
    
    {
        echo "=== SYSTEM LOG SUMMARY ==="
        echo "Recent critical errors:"
        journalctl -p err -n 10 --no-pager 2>/dev/null || echo "Journalctl not accessible"
        echo
        
        echo "=== AUTHENTICATION LOGS ==="
        echo "Recent login attempts:"
        tail -20 /var/log/auth.log 2>/dev/null || echo "Auth log not accessible"
        echo
        
        echo "=== KERNEL MESSAGES ==="
        echo "Recent kernel messages:"
        dmesg | tail -20 2>/dev/null || echo "Kernel messages not accessible"
        echo
        
        echo "=== APACHE/NGINX LOGS ==="
        if [ -f /var/log/apache2/error.log ]; then
            echo "Apache errors (last 10):"
            tail -10 /var/log/apache2/error.log
            echo
        fi
        if [ -f /var/log/nginx/error.log ]; then
            echo "Nginx errors (last 10):"
            tail -10 /var/log/nginx/error.log
            echo
        fi
        
        echo "=== DOCKER LOGS ==="
        if command -v docker >/dev/null 2>&1; then
            echo "Docker daemon logs:"
            journalctl -u docker.service -n 10 --no-pager 2>/dev/null || echo "Docker logs not accessible"
        fi
        echo
        
        echo "=== DISK USAGE LOGS ==="
        echo "Log directory sizes:"
        du -sh /var/log/* 2>/dev/null | sort -hr | head -10 || echo "Log sizes not accessible"
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Generate security report
document_security() {
    print_header "SECURITY INFORMATION"
    
    {
        echo "=== USER ACCOUNTS ==="
        echo "User accounts:"
        cut -d: -f1,3,4,5 /etc/passwd | grep -E ':[0-9]{4}:' || echo "No regular users found"
        echo
        echo "Sudo users:"
        grep -E '^sudo:' /etc/group | cut -d: -f4 || echo "No sudo group found"
        echo
        
        echo "=== SSH CONFIGURATION ==="
        if [ -f /etc/ssh/sshd_config ]; then
            echo "SSH settings:"
            grep -E '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null || echo "SSH config not accessible"
        fi
        echo
        
        echo "=== FAILED LOGIN ATTEMPTS ==="
        echo "Recent failed logins:"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || echo "No failed login logs"
        echo
        
        echo "=== PACKAGE UPDATES ==="
        echo "Available updates:"
        apt list --upgradable 2>/dev/null | head -10 || echo "Update info not available"
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Performance monitoring
monitor_performance() {
    print_header "PERFORMANCE MONITORING"
    
    {
        echo "=== SYSTEM LOAD ==="
        uptime
        echo
        
        echo "=== TOP PROCESSES ==="
        ps aux --sort=-%cpu | head -10
        echo
        
        echo "=== MEMORY USAGE ==="
        free -h
        echo
        echo "Top memory consumers:"
        ps aux --sort=-%mem | head -10
        echo
        
        echo "=== DISK I/O ==="
        if command -v iostat >/dev/null 2>&1; then
            iostat -x 1 1 2>/dev/null || echo "iostat not available"
        else
            echo "iostat not installed (install with: apt install sysstat)"
        fi
        echo
        
        echo "=== NETWORK TRAFFIC ==="
        cat /proc/net/dev
        echo
        
    } | tee -a "$REPORT_FILE"
}

# Show help
show_help() {
    cat << EOF
Server Documentation Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    full        Generate complete documentation report
    hardware    Document hardware information
    software    Document software and packages
    services    Document running services
    network     Document network and IP configuration
    logs        Document system logs
    security    Document security information
    monitor     Show current performance metrics
    watch       Continuous monitoring (Ctrl+C to stop)
    help        Show this help message

Options:
    --output FILE    Specify output file (default: auto-generated)
    --no-file       Don't save to file, only display

Examples:
    $0 full                    # Complete documentation
    $0 hardware               # Hardware info only
    $0 monitor                # Current performance
    $0 watch                  # Continuous monitoring
    $0 full --output server.txt  # Save to specific file

Reports are saved to: $HOME/server-docs

EOF
}

# Continuous monitoring
watch_performance() {
    print_status "Starting continuous monitoring (Press Ctrl+C to stop)"
    
    while true; do
        clear
        echo -e "${CYAN}=== LIVE SERVER MONITORING ===${NC}"
        echo "Last updated: $(date)"
        echo
        
        echo -e "${BLUE}Load Average:${NC} $(uptime | cut -d',' -f3-)"
        echo -e "${BLUE}Memory:${NC} $(free | grep Mem | awk '{printf "%.1f%% used", $3/$2 * 100.0}')"
        echo -e "${BLUE}Disk:${NC} $(df / | tail -1 | awk '{print $5 " used"}')"
        echo
        
        echo -e "${YELLOW}Top Processes:${NC}"
        ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "%-10s %5s%% %5s%% %s\n", $1, $3, $4, $11}'
        echo
        
        echo -e "${YELLOW}Docker Containers:${NC}"
        if command -v docker >/dev/null 2>&1; then
            docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | head -6 || echo "Docker not accessible"
        else
            echo "Docker not installed"
        fi
        echo
        
        echo -e "${YELLOW}Network Connections:${NC}"
        ss -tuln | grep LISTEN | wc -l | xargs echo "Listening ports:"
        
        sleep 5
    done
}

# Main function
main() {
    case "${1:-help}" in
        "full")
            init_report
            document_hardware
            document_software
            document_services
            document_network
            document_logs
            document_security
            monitor_performance
            print_status "Complete documentation saved to: $REPORT_FILE"
            ;;
        "hardware")
            init_report
            document_hardware
            ;;
        "software")
            init_report
            document_software
            ;;
        "services")
            init_report
            document_services
            ;;
        "network")
            init_report
            document_network
            ;;
        "logs")
            init_report
            document_logs
            ;;
        "security")
            init_report
            document_security
            ;;
        "monitor")
            monitor_performance
            ;;
        "watch")
            watch_performance
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