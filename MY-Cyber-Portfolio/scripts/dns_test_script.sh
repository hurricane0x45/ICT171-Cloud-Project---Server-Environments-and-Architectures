#!/bin/bash

# DNS Connection Test Script for Ubuntu Server
# Tests and verifies DNS connectivity and resolution
# Author: System Administrator
# Version: 1.0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_FILE="/var/log/dns_test.log"
TIMEOUT=5
VERBOSE=false

# DNS servers to test
PRIMARY_DNS="8.8.8.8"
SECONDARY_DNS="1.1.1.1"
# Try to get local DNS server, handle if systemd-resolved is not available
if command -v systemd-resolve >/dev/null 2>&1; then
    LOCAL_DNS=$(systemd-resolve --status | grep "DNS Servers" | head -1 | awk '{print $3}')
elif command -v resolvectl >/dev/null 2>&1; then
    LOCAL_DNS=$(resolvectl status | grep "DNS Servers" | head -1 | awk '{print $3}')
else
    LOCAL_DNS=""
fi

# Test domains (using space-separated string instead of array for sh compatibility)
TEST_DOMAINS="google.com github.com ubuntu.com docker.com"

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $message"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
    esac
}

# Function to log results
log_result() {
    if [ -n "$LOG_FILE" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -v, --verbose    Enable verbose output"
    echo "  -l, --log-file   Specify log file path (default: /var/log/dns_test.log)"
    echo "  -t, --timeout    Set timeout for DNS queries (default: 5 seconds)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run basic DNS tests"
    echo "  $0 -v                 # Run with verbose output"
    echo "  $0 -t 10              # Run with 10-second timeout"
}

# Function to check if required tools are installed
check_dependencies() {
    local deps="dig nslookup host ping"
    local missing=""
    
    for dep in $deps; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            if [ -z "$missing" ]; then
                missing="$dep"
            else
                missing="$missing $dep"
            fi
        fi
    done
    
    if [ -n "$missing" ]; then
        print_status "FAIL" "Missing dependencies: $missing"
        print_status "INFO" "Install with: sudo apt update && sudo apt install dnsutils iputils-ping"
        exit 1
    fi
}

# Function to test basic connectivity to DNS servers
test_dns_connectivity() {
    print_status "INFO" "Testing DNS server connectivity..."
    
    local dns_servers="$PRIMARY_DNS $SECONDARY_DNS"
    if [ -n "$LOCAL_DNS" ]; then
        dns_servers="$dns_servers $LOCAL_DNS"
    fi
    
    for dns in $dns_servers; do
        if ping -c 1 -W "$TIMEOUT" "$dns" >/dev/null 2>&1; then
            print_status "PASS" "DNS server $dns is reachable"
            log_result "DNS connectivity test passed for $dns"
        else
            print_status "FAIL" "DNS server $dns is not reachable"
            log_result "DNS connectivity test failed for $dns"
        fi
    done
}

# Function to test DNS resolution using different tools
test_dns_resolution() {
    print_status "INFO" "Testing DNS resolution..."
    
    for domain in $TEST_DOMAINS; do
        local success_count=0
        local total_tests=3
        
        # Test with dig
        if dig +time="$TIMEOUT" "$domain" @"$PRIMARY_DNS" >/dev/null 2>&1; then
            success_count=$((success_count + 1))
            [ "$VERBOSE" = true ] && print_status "PASS" "dig resolution for $domain succeeded"
        else
            [ "$VERBOSE" = true ] && print_status "FAIL" "dig resolution for $domain failed"
        fi
        
        # Test with nslookup
        if timeout "$TIMEOUT" nslookup "$domain" "$PRIMARY_DNS" >/dev/null 2>&1; then
            success_count=$((success_count + 1))
            [ "$VERBOSE" = true ] && print_status "PASS" "nslookup resolution for $domain succeeded"
        else
            [ "$VERBOSE" = true ] && print_status "FAIL" "nslookup resolution for $domain failed"
        fi
        
        # Test with host
        if timeout "$TIMEOUT" host "$domain" "$PRIMARY_DNS" >/dev/null 2>&1; then
            success_count=$((success_count + 1))
            [ "$VERBOSE" = true ] && print_status "PASS" "host resolution for $domain succeeded"
        else
            [ "$VERBOSE" = true ] && print_status "FAIL" "host resolution for $domain failed"
        fi
        
        # Overall result for this domain
        if [ $success_count -eq $total_tests ]; then
            print_status "PASS" "All DNS resolution tests passed for $domain"
            log_result "DNS resolution test passed for $domain (3/3 tools)"
        elif [ $success_count -gt 0 ]; then
            print_status "WARN" "Partial DNS resolution success for $domain ($success_count/$total_tests tools)"
            log_result "DNS resolution test partially passed for $domain ($success_count/$total_tests tools)"
        else
            print_status "FAIL" "All DNS resolution tests failed for $domain"
            log_result "DNS resolution test failed for $domain (0/$total_tests tools)"
        fi
    done
}

# Function to test reverse DNS lookup
test_reverse_dns() {
    print_status "INFO" "Testing reverse DNS lookup..."
    
    local test_ips="8.8.8.8 1.1.1.1"
    
    for ip in $test_ips; do
        if dig +time="$TIMEOUT" -x "$ip" @"$PRIMARY_DNS" | grep -q "ANSWER SECTION"; then
            print_status "PASS" "Reverse DNS lookup for $ip succeeded"
            log_result "Reverse DNS test passed for $ip"
        else
            print_status "FAIL" "Reverse DNS lookup for $ip failed"
            log_result "Reverse DNS test failed for $ip"
        fi
    done
}

# Function to check DNS configuration
check_dns_config() {
    print_status "INFO" "Checking DNS configuration..."
    
    # Check /etc/resolv.conf
    if [ -f /etc/resolv.conf ]; then
        local nameservers=$(grep "^nameserver" /etc/resolv.conf | wc -l)
        if [ "$nameservers" -gt 0 ]; then
            print_status "PASS" "Found $nameservers nameserver(s) in /etc/resolv.conf"
            if [ "$VERBOSE" = true ]; then
                grep "^nameserver" /etc/resolv.conf | while read line; do
                    print_status "INFO" "  $line"
                done
            fi
        else
            print_status "WARN" "No nameservers found in /etc/resolv.conf"
        fi
    else
        print_status "WARN" "/etc/resolv.conf not found"
    fi
    
    # Check systemd-resolved status (try multiple commands)
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        print_status "PASS" "systemd-resolved is active"
        if [ "$VERBOSE" = true ]; then
            print_status "INFO" "Current DNS settings:"
            if command -v systemd-resolve >/dev/null 2>&1; then
                systemd-resolve --status | grep -A 10 "Global" 2>/dev/null || true
            elif command -v resolvectl >/dev/null 2>&1; then
                resolvectl status | grep -A 10 "Global" 2>/dev/null || true
            fi
        fi
    else
        print_status "WARN" "systemd-resolved is not active"
    fi
}

# Function to test DNS over specific ports
test_dns_ports() {
    print_status "INFO" "Testing DNS ports..."
    
    # Test UDP port 53 (using nc if available, otherwise skip)
    if command -v nc >/dev/null 2>&1; then
        if timeout "$TIMEOUT" nc -u -z "$PRIMARY_DNS" 53 >/dev/null 2>&1; then
            print_status "PASS" "UDP port 53 is accessible on $PRIMARY_DNS"
        else
            print_status "FAIL" "UDP port 53 is not accessible on $PRIMARY_DNS"
        fi
        
        # Test TCP port 53
        if timeout "$TIMEOUT" nc -z "$PRIMARY_DNS" 53 >/dev/null 2>&1; then
            print_status "PASS" "TCP port 53 is accessible on $PRIMARY_DNS"
        else
            print_status "WARN" "TCP port 53 is not accessible on $PRIMARY_DNS"
        fi
    else
        print_status "WARN" "netcat (nc) not available, skipping port tests"
        print_status "INFO" "Install with: sudo apt install netcat-openbsd"
    fi
}

# Function to measure DNS response times
measure_dns_performance() {
    print_status "INFO" "Measuring DNS performance..."
    
    local domain="google.com"
    local total_time=0
    local successful_queries=0
    local queries=5
    
    for i in $(seq 1 $queries); do
        local start_time=$(date +%s%3N)
        if dig +time="$TIMEOUT" "$domain" @"$PRIMARY_DNS" >/dev/null 2>&1; then
            local end_time=$(date +%s%3N)
            local query_time=$((end_time - start_time))
            total_time=$((total_time + query_time))
            successful_queries=$((successful_queries + 1))
            [ "$VERBOSE" = true ] && print_status "INFO" "Query $i: ${query_time}ms"
        fi
    done
    
    if [ $successful_queries -gt 0 ]; then
        local avg_time=$((total_time / successful_queries))
        if [ $avg_time -lt 100 ]; then
            print_status "PASS" "Average DNS response time: ${avg_time}ms (excellent)"
        elif [ $avg_time -lt 500 ]; then
            print_status "PASS" "Average DNS response time: ${avg_time}ms (good)"
        else
            print_status "WARN" "Average DNS response time: ${avg_time}ms (slow)"
        fi
        log_result "DNS performance test: ${avg_time}ms average over $successful_queries queries"
    else
        print_status "FAIL" "No successful DNS queries for performance measurement"
        log_result "DNS performance test failed - no successful queries"
    fi
}

# Function to generate summary report
generate_summary() {
    print_status "INFO" "=== DNS Test Summary ==="
    echo "Test completed at: $(date)"
    if [ -n "$LOG_FILE" ]; then
        echo "Log file: $LOG_FILE"
        echo ""
        echo "For detailed logs, run: tail -n 20 $LOG_FILE"
    else
        echo "Logging was disabled due to file permissions"
    fi
    echo "To monitor DNS continuously, consider running this script via cron"
}

# Main function
main() {
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -l|--log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Create log file if it doesn't exist
    if touch "$LOG_FILE" 2>/dev/null; then
        print_status "INFO" "Using log file: $LOG_FILE"
    else
        LOG_FILE="./dns_test.log"
        print_status "WARN" "Cannot write to specified location, using local log file: $LOG_FILE"
        touch "$LOG_FILE" 2>/dev/null || {
            print_status "WARN" "Cannot create log file, logging disabled"
            LOG_FILE=""
        }
    fi
    
    print_status "INFO" "Starting DNS connection and verification tests..."
    print_status "INFO" "Timeout set to: $TIMEOUT seconds"
    print_status "INFO" "Log file: $LOG_FILE"
    echo ""
    
    # Run all tests
    check_dependencies
    check_dns_config
    test_dns_connectivity
    test_dns_resolution
    test_reverse_dns
    test_dns_ports
    measure_dns_performance
    
    echo ""
    generate_summary
    
    log_result "DNS test script completed successfully"
}

# Run main function with all arguments
main "$@"