#!/bin/bash

# Certbot Certificate Management Script for Ubuntu Docker Server
# This script helps view, test, and manage SSL certificates

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if certbot is installed
check_certbot() {
    print_status "Checking if Certbot is installed..."
    if command -v certbot &> /dev/null; then
        print_success "Certbot is installed: $(certbot --version)"
        return 0
    else
        print_error "Certbot is not installed"
        return 1
    fi
}

# Function to list all certificates
list_certificates() {
    print_status "Listing all SSL certificates..."
    echo "=================================================="
    
    if ! certbot certificates 2>/dev/null; then
        print_warning "No certificates found or certbot command failed"
        return 1
    fi
    
    echo "=================================================="
}

# Function to show certificate details
show_certificate_details() {
    if [ -z "$1" ]; then
        echo "Usage: show_certificate_details <domain_name>"
        return 1
    fi
    
    local domain="$1"
    print_status "Showing details for certificate: $domain"
    
    # Check if certificate exists
    if certbot certificates | grep -q "$domain"; then
        echo "Certificate found for $domain"
        echo "=================================================="
        certbot certificates --cert-name "$domain"
        echo "=================================================="
        
        # Show certificate file details using openssl
        local cert_path="/etc/letsencrypt/live/$domain/cert.pem"
        if [ -f "$cert_path" ]; then
            print_status "Certificate file details:"
            openssl x509 -in "$cert_path" -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:|DNS:)"
        fi
    else
        print_error "Certificate for $domain not found"
        return 1
    fi
}

# Function to test certificate renewal (dry run)
test_renewal() {
    print_status "Testing certificate renewal (dry run)..."
    echo "This will simulate renewal without making actual changes"
    echo "=================================================="
    
    if certbot renew --dry-run; then
        print_success "Certificate renewal test passed!"
    else
        print_error "Certificate renewal test failed!"
        return 1
    fi
}

# Function to test specific certificate renewal
test_specific_renewal() {
    if [ -z "$1" ]; then
        echo "Usage: test_specific_renewal <domain_name>"
        return 1
    fi
    
    local domain="$1"
    print_status "Testing renewal for specific certificate: $domain"
    
    if certbot renew --cert-name "$domain" --dry-run; then
        print_success "Renewal test for $domain passed!"
    else
        print_error "Renewal test for $domain failed!"
        return 1
    fi
}

# Function to check certificate expiration
check_expiration() {
    print_status "Checking certificate expiration dates..."
    echo "=================================================="
    
    # Get all certificate names
    local cert_names=$(certbot certificates 2>/dev/null | grep "Certificate Name:" | awk '{print $3}')
    
    if [ -z "$cert_names" ]; then
        print_warning "No certificates found"
        return 1
    fi
    
    for cert_name in $cert_names; do
        local cert_path="/etc/letsencrypt/live/$cert_name/cert.pem"
        if [ -f "$cert_path" ]; then
            local expiry_date=$(openssl x509 -in "$cert_path" -noout -enddate | cut -d= -f2)
            local expiry_epoch=$(date -d "$expiry_date" +%s)
            local current_epoch=$(date +%s)
            local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            if [ $days_until_expiry -lt 0 ]; then
                print_error "$cert_name: EXPIRED $((days_until_expiry * -1)) days ago"
            elif [ $days_until_expiry -lt 30 ]; then
                print_warning "$cert_name: Expires in $days_until_expiry days ($expiry_date)"
            else
                print_success "$cert_name: Expires in $days_until_expiry days ($expiry_date)"
            fi
        fi
    done
    echo "=================================================="
}

# Function to check nginx/apache configuration
check_webserver_config() {
    print_status "Checking web server configuration..."
    
    # Check for Nginx
    if command -v nginx &> /dev/null; then
        print_status "Nginx detected - testing configuration..."
        if nginx -t; then
            print_success "Nginx configuration is valid"
        else
            print_error "Nginx configuration has errors"
        fi
    fi
    
    # Check for Apache
    if command -v apache2ctl &> /dev/null; then
        print_status "Apache detected - testing configuration..."
        if apache2ctl configtest; then
            print_success "Apache configuration is valid"
        else
            print_error "Apache configuration has errors"
        fi
    fi
    
    # If neither found, check if running in Docker
    if [ -f /.dockerenv ]; then
        print_status "Running in Docker container - web server may be in another container"
    fi
}

# Function to show system info
show_system_info() {
    print_status "System Information:"
    echo "=================================================="
    echo "OS: $(lsb_release -d | cut -f2)"
    echo "Kernel: $(uname -r)"
    echo "Date: $(date)"
    echo "Uptime: $(uptime -p)"
    
    if [ -f /.dockerenv ]; then
        echo "Environment: Docker Container"
    else
        echo "Environment: Host System"
    fi
    
    echo "Disk usage for /etc/letsencrypt:"
    du -sh /etc/letsencrypt 2>/dev/null || echo "Certbot directory not found"
    echo "=================================================="
}

# Function to show help
show_help() {
    echo "Certbot Certificate Management Script"
    echo "====================================="
    echo ""
    echo "Usage: $0 [OPTION] [DOMAIN]"
    echo ""
    echo "Options:"
    echo "  -l, --list              List all certificates"
    echo "  -d, --details DOMAIN    Show details for specific certificate"
    echo "  -t, --test              Test certificate renewal (dry run)"
    echo "  -ts, --test-specific DOMAIN  Test renewal for specific certificate"
    echo "  -e, --expiration        Check certificate expiration dates"
    echo "  -w, --webserver         Check web server configuration"
    echo "  -s, --system            Show system information"
    echo "  -a, --all               Run all checks"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --list"
    echo "  $0 --details example.com"
    echo "  $0 --test"
    echo "  $0 --all"
}

# Main script logic
main() {
    echo "========================================"
    echo "  Certbot Certificate Management Tool  "
    echo "========================================"
    echo ""
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        print_warning "This script should be run as root or with sudo for full functionality"
        echo ""
    fi
    
    # Parse command line arguments
    case "$1" in
        -l|--list)
            check_certbot && list_certificates
            ;;
        -d|--details)
            if [ -z "$2" ]; then
                print_error "Domain name required for --details option"
                echo "Usage: $0 --details <domain_name>"
                exit 1
            fi
            check_certbot && show_certificate_details "$2"
            ;;
        -t|--test)
            check_certbot && test_renewal
            ;;
        -ts|--test-specific)
            if [ -z "$2" ]; then
                print_error "Domain name required for --test-specific option"
                echo "Usage: $0 --test-specific <domain_name>"
                exit 1
            fi
            check_certbot && test_specific_renewal "$2"
            ;;
        -e|--expiration)
            check_certbot && check_expiration
            ;;
        -w|--webserver)
            check_webserver_config
            ;;
        -s|--system)
            show_system_info
            ;;
        -a|--all)
            show_system_info
            echo ""
            if check_certbot; then
                echo ""
                list_certificates
                echo ""
                check_expiration
                echo ""
                test_renewal
            fi
            echo ""
            check_webserver_config
            ;;
        -h|--help|"")
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"