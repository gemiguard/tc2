#!/bin/bash
# =============================================================================
# Secure VPS Setup Script - Debian 12 (IMPROVED VERSION)
# WireGuard VPN + System Hardening + Monitoring
# =============================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Safer word splitting

# Terminal colors
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration Variables
readonly SCRIPT_VERSION="2.0.0"
readonly CONFIG_FILE="vpn_setup.conf"
readonly LOG_FILE="/var/log/secure_vpn_setup.log"
readonly BACKUP_DIR="/root/vpn_setup_backups"
readonly STATE_FILE="${BACKUP_DIR}/.setup_state"

# Default configuration
WG_PORT="${WG_PORT:-51820}"
WG_SERVER_IP="${WG_SERVER_IP:-10.10.10.1/24}"
SSH_PORT="${SSH_PORT:-22}"
INSTALL_NETDATA="${INSTALL_NETDATA:-true}"
ENABLE_SSL="${ENABLE_SSL:-true}"
PING_TEST_IP="${PING_TEST_IP:-1.1.1.1}"
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
USER_ACCOUNT_NAME="${USER_ACCOUNT_NAME:-}"
USER_PASSWORD="${USER_PASSWORD:-}"
HOST_FQDN="${HOST_FQDN:-}"
PUBLIC_IP="${PUBLIC_IP:-}"

# Logging functions with timestamps
log() {
    local msg="$1"
    echo -e "${GREEN}[+] ${msg}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: ${msg}" >> "$LOG_FILE"
}

error() {
    local msg="$1"
    echo -e "${RED}[-] ${msg}${NC}" >&2
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: ${msg}" >> "$LOG_FILE"
    cleanup_on_error
    exit 1
}

warning() {
    local msg="$1"
    echo -e "${YELLOW}[!] ${msg}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: ${msg}" >> "$LOG_FILE"
}

section() {
    local msg="$1"
    echo -e "\n${BLUE}========= ${msg} =========${NC}\n"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SECTION: ${msg}" >> "$LOG_FILE"
}

# Validation functions
validate_port() {
    local port="$1"
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

validate_username() {
    local username="$1"
    if [[ ! "$username" =~ ^[a-z][-a-z0-9_]{0,30}$ ]]; then
        return 1
    fi
    return 0
}

# State management for rollback capability
save_state() {
    local step="$1"
    echo "$step" >> "$STATE_FILE"
    log "Checkpoint: $step"
}

cleanup_on_error() {
    warning "An error occurred. Attempting cleanup..."
    if [ -f "$STATE_FILE" ]; then
        warning "Setup reached these steps before failing:"
        cat "$STATE_FILE" | sed 's/^/  - /' >&2
    fi
    # Add specific rollback logic here based on state file
}

# Check prerequisites
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[-] This script must be run as root${NC}" >&2
        exit 1
    fi
}

check_debian_version() {
    if [ ! -f /etc/debian_version ]; then
        error "This script is designed for Debian systems only"
    fi
    
    local version
    version=$(cat /etc/debian_version | cut -d. -f1)
    if [ "$version" -lt 11 ]; then
        warning "This script is tested on Debian 11+. Your version: $version"
        read -rp "Continue anyway? (yes/no): " response
        if [ "$response" != "yes" ]; then
            exit 1
        fi
    fi
}

# Check and install critical dependencies needed to run this script
check_critical_dependencies() {
    echo -e "${BLUE}Checking critical dependencies...${NC}"
    
    local missing_critical=()
    local critical_packages=(
        "curl"
        "wget" 
        "sudo"
        "gnupg"
    )
    
    # Check which critical packages are missing
    for pkg in "${critical_packages[@]}"; do
        if ! command -v "$pkg" &>/dev/null; then
            missing_critical+=("$pkg")
        fi
    done
    
    # If any critical packages are missing, install them
    if [ ${#missing_critical[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing critical packages: ${missing_critical[*]}${NC}"
        echo -e "${GREEN}[+] Installing critical dependencies...${NC}"
        
        # Update package lists first
        if ! apt-get update -qq; then
            echo -e "${RED}[-] Failed to update package lists${NC}" >&2
            echo -e "${RED}[-] Please ensure this system has internet connectivity${NC}" >&2
            exit 1
        fi
        
        # Install missing critical packages
        if ! apt-get install -y -qq "${missing_critical[@]}"; then
            echo -e "${RED}[-] Failed to install critical dependencies: ${missing_critical[*]}${NC}" >&2
            exit 1
        fi
        
        echo -e "${GREEN}[+] Critical dependencies installed${NC}"
    else
        echo -e "${GREEN}[+] All critical dependencies present${NC}"
    fi
}

# Enhanced check for bash version
check_bash_version() {
    if [ -z "${BASH_VERSION}" ]; then
        echo -e "${RED}[-] This script requires bash${NC}" >&2
        exit 1
    fi
    
    local bash_major="${BASH_VERSINFO[0]}"
    if [ "$bash_major" -lt 4 ]; then
        echo -e "${YELLOW}[!] Warning: Bash version ${BASH_VERSION} detected. Version 4+ recommended.${NC}"
        read -rp "Continue anyway? (yes/no): " response
        if [ "$response" != "yes" ]; then
            exit 1
        fi
    fi
}

# Initialize
init_log() {
    mkdir -p "$BACKUP_DIR"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    log "=== VPS Setup Script v${SCRIPT_VERSION} ==="
    log "Starting VPS hardening and WireGuard setup..."
    log "Logging to $LOG_FILE"
    
    # Initialize state tracking
    : > "$STATE_FILE"
}

# Load and validate configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        log "Loading configuration from $CONFIG_FILE"
        # Safely source config file
        if bash -n "$CONFIG_FILE" 2>/dev/null; then
            # shellcheck source=/dev/null
            source "$CONFIG_FILE"
        else
            error "Configuration file has syntax errors"
        fi
    fi
    
    # Validate loaded configuration
    if [ -n "$SSH_PORT" ] && ! validate_port "$SSH_PORT"; then
        error "Invalid SSH_PORT: $SSH_PORT"
    fi
    
    if [ -n "$WG_PORT" ] && ! validate_port "$WG_PORT"; then
        error "Invalid WG_PORT: $WG_PORT"
    fi
}

# Network utilities with improved error handling
get_public_ip() {
    if [ -z "$PUBLIC_IP" ]; then
        log "Detecting public IP address..."
        
        # Try multiple services
        local services=(
            "https://api.ipify.org"
            "https://ifconfig.me/ip"
            "https://icanhazip.com"
        )
        
        for service in "${services[@]}"; do
            PUBLIC_IP=$(curl -s --max-time 10 "$service" 2>/dev/null | tr -d '[:space:]')
            if validate_ip "$PUBLIC_IP"; then
                log "Public IP detected: $PUBLIC_IP"
                return 0
            fi
        done
        
        warning "Could not determine public IP automatically"
        while true; do
            read -rp "Please enter your server's public IP address: " PUBLIC_IP
            if validate_ip "$PUBLIC_IP"; then
                break
            fi
            warning "Invalid IP address format. Please try again."
        done
    fi
    log "Using public IP: $PUBLIC_IP"
}

reverse_dns_lookup() {
    local ip="$1"
    timeout 10 nslookup "$ip" 2>/dev/null | grep -e = | awk -F= '{print $2}' | tr -d ' \t' | sed 's/\.$//g' | head -1
}

forward_dns_lookup() {
    local hostname="$1"
    timeout 10 nslookup "$hostname" 2>/dev/null | grep -v '#' | grep 'Address:' | awk '{print $2}' | tail -1
}

get_host_fqdn() {
    if [ -z "$HOST_FQDN" ]; then
        local detected_fqdn
        detected_fqdn=$(reverse_dns_lookup "$PUBLIC_IP")
        
        if [ -n "$detected_fqdn" ]; then
            log "Auto-detected hostname: $detected_fqdn"
            read -rp "Press ENTER to use '$detected_fqdn' or type alternative: " response
            HOST_FQDN="${response:-$detected_fqdn}"
        else
            while [ -z "$HOST_FQDN" ]; do
                read -rp "Enter fully qualified domain name (e.g., vpn.example.com): " HOST_FQDN
            done
        fi
    fi
    
    # Verify DNS resolution
    local resolved_ip
    resolved_ip=$(forward_dns_lookup "$HOST_FQDN")
    
    if [ -z "$resolved_ip" ]; then
        warning "DNS lookup for $HOST_FQDN failed"
        read -rp "Continue anyway? (yes/no): " response
        [ "$response" = "yes" ] || error "User aborted due to DNS issues"
    elif [ "$resolved_ip" != "$PUBLIC_IP" ]; then
        warning "DNS mismatch: $HOST_FQDN resolves to $resolved_ip, but server IP is $PUBLIC_IP"
        read -rp "Continue anyway? (yes/no): " response
        [ "$response" = "yes" ] || error "User aborted due to DNS mismatch"
    else
        log "DNS verification successful: $HOST_FQDN -> $PUBLIC_IP"
    fi
}

# Test network connectivity
test_network() {
    log "Testing network connectivity to ${PING_TEST_IP}..."
    if ping -c 3 -W 5 "$PING_TEST_IP" &>/dev/null; then
        log "Network connectivity OK"
        save_state "network_test"
    else
        error "Network connectivity test failed. Please check your connection."
    fi
}

# Get and validate SSH public key
get_pubkey() {
    if [ -z "$SSH_PUBLIC_KEY" ]; then
        echo ""
        echo "You must provide an SSH public key for secure access."
        echo "Without this, you may be locked out after SSH hardening."
        echo ""
        
        while true; do
            read -rp "Paste your SSH public key: " SSH_PUBLIC_KEY
            
            # Basic validation of SSH key format
            if [[ "$SSH_PUBLIC_KEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)[[:space:]] ]]; then
                log "SSH public key accepted"
                break
            else
                warning "This doesn't appear to be a valid SSH public key"
                read -rp "Try again? (yes/no): " retry
                [ "$retry" = "yes" ] || error "Valid SSH public key is required"
            fi
        done
    fi
}

# Install SSH public key with proper permissions
install_user_ssh_pubkey() {
    local username="$1"
    local homedir="$2"
    local pubkey="$3"
    
    mkdir -p "${homedir}/.ssh"
    echo "$pubkey" >> "${homedir}/.ssh/authorized_keys"
    chown -R "${username}:${username}" "${homedir}/.ssh"
    chmod 700 "${homedir}/.ssh"
    chmod 600 "${homedir}/.ssh/authorized_keys"
    
    log "SSH public key installed for $username"
}

# Select and validate username
select_user_name() {
    if [ -n "$USER_ACCOUNT_NAME" ]; then
        if ! validate_username "$USER_ACCOUNT_NAME"; then
            error "Configured username '$USER_ACCOUNT_NAME' is invalid"
        fi
        
        # Check if configured user exists
        if getent passwd "$USER_ACCOUNT_NAME" &>/dev/null; then
            log "User '$USER_ACCOUNT_NAME' already exists - will use existing account"
            return
        fi
        
        log "Using configured username: $USER_ACCOUNT_NAME"
        return
    fi
    
    while true; do
        read -rp "Enter username for VPS account and Netdata login: " response
        response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
        
        if [ -z "$response" ]; then
            warning "Username cannot be empty"
            continue
        fi
        
        if ! validate_username "$response"; then
            warning "Invalid username format. Use lowercase letters, numbers, hyphens, underscores only."
            continue
        fi
        
        if getent passwd "$response" &>/dev/null; then
            warning "Username '$response' already exists"
            read -rp "Use existing user '$response'? (yes/no): " use_existing
            if [ "$use_existing" = "yes" ]; then
                USER_ACCOUNT_NAME="$response"
                log "Using existing user: $USER_ACCOUNT_NAME"
                break
            else
                log "Please choose a different username"
                continue
            fi
        fi
        
        USER_ACCOUNT_NAME="$response"
        log "Username set to: $USER_ACCOUNT_NAME"
        break
    done
    
    save_state "user_selected"
}

# Prompt for user password
get_user_password() {
    if [ -n "$USER_PASSWORD" ]; then
        log "Using pre-configured password"
        return
    fi
    
    # Check if user already exists and has a password
    if id "$USER_ACCOUNT_NAME" &>/dev/null; then
        if ! passwd -S "$USER_ACCOUNT_NAME" | grep -q " NP "; then
            log "User already has a password set"
            read -rp "Set a new password for this user? (yes/no): " change_pass
            if [ "$change_pass" != "yes" ]; then
                log "Keeping existing password"
                USER_PASSWORD=""
                return
            fi
        fi
    fi
    
    echo ""
    echo "Please set a password for user '${USER_ACCOUNT_NAME}'"
    echo "This password will be used for:"
    echo "  - Console/TTY login"
    echo "  - Netdata web interface authentication"
    echo "  - Any services requiring user authentication"
    echo ""
    
    while true; do
        read -rsp "Enter password: " password1
        echo ""
        
        if [ -z "$password1" ]; then
            warning "Password cannot be empty"
            continue
        fi
        
        if [ ${#password1} -lt 8 ]; then
            warning "Password must be at least 8 characters long"
            continue
        fi
        
        read -rsp "Confirm password: " password2
        echo ""
        
        if [ "$password1" != "$password2" ]; then
            warning "Passwords do not match. Please try again."
            continue
        fi
        
        USER_PASSWORD="$password1"
        log "Password set successfully"
        break
    done
}

# Preseed postfix to avoid interactive prompts
preseed_postfix_settings() {
    log "Pre-configuring mail system..."
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections
    echo "postfix postfix/mailname string $(hostname).localdomain" | debconf-set-selections
}

# Install packages with retry logic
install_packages() {
    section "Installing Required Packages"
    
    log "Updating package database..."
    local retry=0
    while [ $retry -lt 3 ]; do
        if apt-get update; then
            break
        fi
        retry=$((retry + 1))
        warning "Package update failed, attempt $retry/3"
        sleep 5
    done
    
    [ $retry -lt 3 ] || error "Failed to update package database after 3 attempts"
    
    log "Upgrading existing packages..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
    
    log "Installing required packages..."
    # Package breakdown:
    # - Core utilities: sudo, curl, wget, gnupg2, ca-certificates (should already be installed by check_critical_dependencies)
    # - Network/repo tools: software-properties-common, apt-transport-https, lsb-release
    # - Security: unattended-upgrades, fail2ban, ufw
    # - VPN: wireguard, qrencode (for QR codes)
    # - Web server: nginx, apache2-utils (for htpasswd), certbot, python3-certbot-nginx
    # - System tools: git, python3, python3-pip, python3-venv, rsyslog
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        sudo curl wget gnupg2 software-properties-common apt-transport-https \
        ca-certificates lsb-release unattended-upgrades fail2ban ufw git \
        python3 python3-pip python3-venv qrencode wireguard nginx apache2-utils \
        certbot python3-certbot-nginx rsyslog \
        || error "Failed to install required packages"
    
    save_state "packages_installed"
    log "All required packages installed successfully"
}

# Configure automatic security updates
setup_unattended_upgrades() {
    section "Configuring Automatic Security Updates"
    
    # Backup existing configuration
    [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && \
        cp /etc/apt/apt.conf.d/20auto-upgrades "${BACKUP_DIR}/20auto-upgrades.bak"
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Email notifications (configure SMTP separately if needed)
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "on-change";
EOF

    # Test the configuration
    if ! unattended-upgrade --dry-run --debug; then
        warning "Unattended-upgrades dry-run reported issues"
    fi
    
    save_state "auto_updates_configured"
    log "Automatic security updates configured successfully"
}

# System hardening with sysctl
harden_sysctl() {
    section "Hardening Network Stack"
    
    [ -f /etc/sysctl.d/99-security.conf ] && \
        cp /etc/sysctl.d/99-security.conf "${BACKUP_DIR}/99-security.conf.bak"
    
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Forwarding (required for VPN)
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP ping broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP hardening
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Increase system file descriptors
fs.file-max = 65535

# Kernel hardening
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
EOF

    # Apply settings
    if sysctl -p /etc/sysctl.d/99-security.conf; then
        save_state "sysctl_hardened"
        log "Network hardening applied successfully"
    else
        warning "Some sysctl parameters could not be applied"
    fi
}

# Enhanced SSH security
secure_ssh() {
    section "Securing SSH Configuration"
    
    # Backup original configuration
    cp /etc/ssh/sshd_config "${BACKUP_DIR}/sshd_config.$(date +%Y%m%d_%H%M%S).bak"
    
    # Generate strong host keys if missing
    if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
        log "Generating ED25519 host key..."
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    fi
    
    if [[ ! -f /etc/ssh/ssh_host_rsa_key ]]; then
        log "Generating RSA host key..."
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q
    fi
    
    log "Creating hardened SSH configuration..."
    cat > /etc/ssh/sshd_config << EOF
# SSH Server Configuration - Hardened
Port ${SSH_PORT}
AddressFamily inet
Protocol 2

# Host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# Security limits
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60

# Allowed users
AllowUsers ${USER_ACCOUNT_NAME}

# X11 and forwarding
X11Forwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no

# Keep alive
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Modern crypto algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# SFTP
Subsystem sftp /usr/lib/openssh/sftp-server

# Misc
PrintMotd no
DebianBanner no
EOF

    # Test SSH configuration
    if ! sshd -t; then
        error "SSH configuration test failed"
    fi
    
    # Create user if doesn't exist
    if ! id "$USER_ACCOUNT_NAME" &>/dev/null; then
        log "Creating user account: $USER_ACCOUNT_NAME"
        useradd -m -s /bin/bash "$USER_ACCOUNT_NAME"
        usermod -aG sudo "$USER_ACCOUNT_NAME"
        log "User '$USER_ACCOUNT_NAME' created"
    else
        log "User '$USER_ACCOUNT_NAME' already exists"
        
        # Ensure user is in sudo group
        if ! groups "$USER_ACCOUNT_NAME" | grep -q '\bsudo\b'; then
            log "Adding existing user to sudo group"
            usermod -aG sudo "$USER_ACCOUNT_NAME"
        fi
    fi
    
    # Set user password (if one was provided or prompted for)
    if [ -n "$USER_PASSWORD" ]; then
        log "Setting password for user $USER_ACCOUNT_NAME"
        echo "${USER_ACCOUNT_NAME}:${USER_PASSWORD}" | chpasswd
        log "Password set successfully"
    fi
    
    # Configure passwordless sudo
    log "Configuring passwordless sudo for $USER_ACCOUNT_NAME"
    SUDOERS_FILE="/etc/sudoers.d/${USER_ACCOUNT_NAME}"
    
    # Create sudoers.d file (safer than modifying /etc/sudoers directly)
    echo "${USER_ACCOUNT_NAME} ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"
    
    # Validate sudoers file
    if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        log "Passwordless sudo configured successfully"
    else
        error "Failed to configure passwordless sudo - sudoers syntax error"
    fi
    
    # Restart SSH with verification
    log "Restarting SSH service..."
    if systemctl restart sshd; then
        sleep 2
        if systemctl is-active --quiet sshd; then
            save_state "ssh_secured"
            log "SSH secured and verified successfully"
        else
            error "SSH service failed to start after configuration"
        fi
    else
        error "Failed to restart SSH service"
    fi
    
    warning "IMPORTANT: Test SSH access in a new session before closing this one!"
}

# Configure firewall with fail2ban
setup_firewall() {
    section "Configuring Firewall"
    
    log "Configuring UFW firewall..."
    
    # Default policies
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (must be first!)
    ufw allow "${SSH_PORT}/tcp" comment 'SSH'
    
    # Allow VPN
    ufw allow "${WG_PORT}/udp" comment 'WireGuard VPN'
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable firewall
    log "Enabling UFW..."
    echo "y" | ufw enable
    
    # Configure fail2ban
    log "Configuring Fail2Ban..."
    
    [ -f /etc/fail2ban/jail.local ] && \
        cp /etc/fail2ban/jail.local "${BACKUP_DIR}/jail.local.bak"
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/*error.log
maxretry = 5

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/*access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/*access.log
maxretry = 2
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    save_state "firewall_configured"
    log "Firewall and Fail2Ban configured successfully"
}

# Install and configure WireGuard
install_wireguard() {
    section "Installing WireGuard VPN"
    
    # Create directory structure
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    
    # Generate server keys
    log "Generating WireGuard server keys..."
    wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
    chmod 600 /etc/wireguard/server.key
    chmod 644 /etc/wireguard/server.pub
    
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server.key)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server.pub)
    
    # Detect network interface
    DEFAULT_INTERFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    if [ -z "$DEFAULT_INTERFACE" ]; then
        warning "Could not detect default interface, trying common names..."
        for iface in eth0 ens3 enp0s3 ens18; do
            if ip link show "$iface" &>/dev/null; then
                DEFAULT_INTERFACE="$iface"
                break
            fi
        done
    fi
    
    if [ -z "$DEFAULT_INTERFACE" ]; then
        error "Could not determine network interface"
    fi
    
    log "Using interface: $DEFAULT_INTERFACE"
    
    # Create server configuration
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = ${WG_SERVER_IP}
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVATE_KEY}
SaveConfig = false

# Firewall rules
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PostUp = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${DEFAULT_INTERFACE} -j MASQUERADE

# First client will be added here
EOF

    chmod 600 /etc/wireguard/wg0.conf
    
    # Generate first client
    log "Creating initial client configuration..."
    create_wireguard_client "client1" "10.10.10.2"
    
    # Enable and start WireGuard
    log "Starting WireGuard service..."
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    # Verify WireGuard is running
    if systemctl is-active --quiet wg-quick@wg0; then
        save_state "wireguard_installed"
        log "WireGuard VPN installed and running"
    else
        error "WireGuard service failed to start"
    fi
}

# Helper function to create WireGuard clients
# NOTE: This adds clients to the config file. 
# If wg0 interface is already running, you need to reload it after using this function:
#   systemctl reload wg-quick@wg0  or  wg-quick down wg0 && wg-quick up wg0
create_wireguard_client() {
    local client_name="$1"
    local client_ip="$2"
    
    log "Creating client: $client_name ($client_ip)"
    
    # Generate client keys
    wg genkey | tee "/etc/wireguard/clients/${client_name}.key" | wg pubkey > "/etc/wireguard/clients/${client_name}.pub"
    chmod 600 "/etc/wireguard/clients/${client_name}.key"
    chmod 644 "/etc/wireguard/clients/${client_name}.pub"
    
    local client_private_key client_public_key
    client_private_key=$(cat "/etc/wireguard/clients/${client_name}.key")
    client_public_key=$(cat "/etc/wireguard/clients/${client_name}.pub")
    
    # Create client configuration
    cat > "/etc/wireguard/clients/${client_name}.conf" << EOF
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${PUBLIC_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    chmod 644 "/etc/wireguard/clients/${client_name}.conf"
    
    # Generate QR code
    qrencode -t ansiutf8 < "/etc/wireguard/clients/${client_name}.conf" > "/etc/wireguard/clients/${client_name}_qr.txt"
    
    # Add peer to server configuration file (not using wg set since interface may not be up yet)
    cat >> /etc/wireguard/wg0.conf << EOF

[Peer]
# ${client_name}
PublicKey = ${client_public_key}
AllowedIPs = ${client_ip}/32
EOF
    
    log "Client $client_name created successfully"
}

# Install WGDashboard with proper systemd service
install_wgdashboard() {
    section "Installing WireGuard Dashboard"
    
    # Remove any existing installation
    if [ -d /opt/WGDashboard ]; then
        log "Removing existing WGDashboard installation..."
        systemctl stop wgdashboard 2>/dev/null || true
        systemctl disable wgdashboard 2>/dev/null || true
        rm -rf /opt/WGDashboard
    fi
    
    # Clone repository
    log "Cloning WGDashboard repository..."
    cd /opt || error "Failed to access /opt directory"
    
    if ! git clone -q https://github.com/donaldzou/WGDashboard.git; then
        error "Failed to clone WGDashboard repository"
    fi
    
    cd WGDashboard/src || error "WGDashboard source directory not found"
    
    # Create required directories
    mkdir -p log db
    chmod +x wgd.sh
    
    # Install dependencies
    log "Installing WGDashboard..."
    if ! ./wgd.sh install; then
        error "WGDashboard installation failed"
    fi
    
    # Create proper systemd service
    cat > /etc/systemd/system/wgdashboard.service << 'EOF'
[Unit]
Description=WireGuard Dashboard
Documentation=https://github.com/donaldzou/WGDashboard
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=forking
User=root
WorkingDirectory=/opt/WGDashboard/src
ExecStart=/opt/WGDashboard/src/wgd.sh start
ExecStop=/opt/WGDashboard/src/wgd.sh stop
ExecReload=/opt/WGDashboard/src/wgd.sh restart
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/wgdashboard.log
StandardError=append:/var/log/wgdashboard.log

[Install]
WantedBy=multi-user.target
EOF

    # Configure WGDashboard
    log "Configuring WGDashboard..."
    
    # Set secure defaults in configuration
    if [ -f "/opt/WGDashboard/src/wg-dashboard.ini" ]; then
        sed -i 's/app_ip = 0.0.0.0/app_ip = 127.0.0.1/' /opt/WGDashboard/src/wg-dashboard.ini
        sed -i 's/app_port = 10086/app_port = 10086/' /opt/WGDashboard/src/wg-dashboard.ini
    fi
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable wgdashboard
    systemctl start wgdashboard
    
    # Verify service is running
    sleep 3
    if systemctl is-active --quiet wgdashboard; then
        save_state "wgdashboard_installed"
        log "WGDashboard installed and running"
        warning "Default credentials: admin/admin - CHANGE IMMEDIATELY!"
    else
        warning "WGDashboard service may not have started correctly"
        systemctl status wgdashboard --no-pager
    fi
}

# Install and configure Netdata
install_netdata() {
    section "Installing Netdata Monitoring"
    
    if [ "$INSTALL_NETDATA" != true ]; then
        log "Skipping Netdata installation (disabled in config)"
        return
    fi
    
    log "Downloading Netdata installer..."
    
    # Install Netdata
    if bash <(curl -Ss https://get.netdata.cloud/kickstart.sh) \
        --stable-channel \
        --disable-telemetry \
        --dont-wait \
        --no-updates \
        --non-interactive; then
        log "Netdata installed successfully"
    else
        error "Netdata installation failed"
    fi
    
    # Configure Netdata for local access only
    log "Configuring Netdata..."
    
    # Backup original config
    [ -f /etc/netdata/netdata.conf ] && \
        cp /etc/netdata/netdata.conf "${BACKUP_DIR}/netdata.conf.bak"
    
    cat > /etc/netdata/netdata.conf << 'EOF'
[global]
    run as user = netdata
    web files owner = root
    web files group = root
    memory mode = dbengine

[web]
    default port = 19999
    bind to = 127.0.0.1
    allow connections from = localhost
    enable gzip compression = yes

[db]
    update every = 1
    mode = dbengine
    storage tiers = 3
    dbengine page cache size MB = 32
    dbengine disk space MB = 256
EOF

    # Disable cloud features
    mkdir -p /etc/netdata
    cat > /etc/netdata/cloud.conf << 'EOF'
[global]
    enabled = no
    cloud base url = 
EOF

    # Configure additional monitoring
    cat > /etc/netdata/python.d.conf << 'EOF'
wireguard:
  name: 'local'
  config:
    - name: 'wg0'
EOF

    # Restart Netdata
    systemctl restart netdata
    
    # Verify service
    if systemctl is-active --quiet netdata; then
        save_state "netdata_installed"
        log "Netdata monitoring installed and configured"
    else
        warning "Netdata service may not be running correctly"
    fi
}

# Configure Nginx reverse proxy with security headers
configure_nginx() {
    section "Configuring Nginx Reverse Proxy"
    
    # Backup default config
    [ -f /etc/nginx/sites-available/default ] && \
        cp /etc/nginx/sites-available/default "${BACKUP_DIR}/nginx_default.bak"
    
    # Create htpasswd for Netdata
    log "Setting up HTTP authentication for Netdata..."
    log "Username: $USER_ACCOUNT_NAME"
    
    if ! htpasswd -c /etc/nginx/.htpasswd "$USER_ACCOUNT_NAME"; then
        error "Failed to create htpasswd file"
    fi
    
    chmod 644 /etc/nginx/.htpasswd
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/default << 'EOF'
upstream netdata {
    server 127.0.0.1:19999;
    keepalive 64;
}

upstream wgdashboard {
    server 127.0.0.1:10086;
    keepalive 64;
}

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=wgdash_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=netdata_limit:10m rate=20r/s;

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Hide server version
    server_tokens off;
    
    # Netdata monitoring
    location = /netdata {
        return 301 $scheme://$host/netdata/;
    }
    
    location ~ ^/netdata/(?<ndpath>.*) {
        limit_req zone=netdata_limit burst=20;
        
        auth_basic "Netdata Monitoring";
        auth_basic_user_file /etc/nginx/.htpasswd;
        
        proxy_redirect off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Server $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_pass_request_headers on;
        proxy_set_header Connection "keep-alive";
        proxy_store off;
        
        proxy_pass http://netdata/$ndpath$is_args$args;
        
        gzip on;
        gzip_proxied any;
        gzip_types *;
        
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
    
    # WireGuard Dashboard
    location / {
        limit_req zone=wgdash_limit burst=15;
        
        proxy_pass http://wgdashboard;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for dashboard
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
    
    # Block common exploit attempts
    location ~ /(\.git|\.env|\.htaccess|\.htpasswd|wp-config\.php) {
        deny all;
        return 404;
    }
}
EOF

    # Test Nginx configuration
    if ! nginx -t; then
        error "Nginx configuration test failed"
    fi
    
    # Restart Nginx
    systemctl restart nginx || error "Failed to restart Nginx"
    
    # Configure SSL if enabled
    if [ "$ENABLE_SSL" = true ]; then
        log "Requesting SSL certificate from Let's Encrypt..."
        
        if certbot --nginx \
            -d "$HOST_FQDN" \
            --non-interactive \
            --agree-tos \
            --email "root@${HOST_FQDN}" \
            --redirect \
            --hsts \
            --staple-ocsp; then
            
            log "SSL certificate obtained successfully"
            
            # Add additional security headers for HTTPS
            if ! grep -q "ssl_stapling" /etc/nginx/sites-available/default; then
                sed -i '/server_name/a \
    # SSL Security\
    ssl_stapling on;\
    ssl_stapling_verify on;\
    ssl_session_timeout 1d;\
    ssl_session_cache shared:SSL:50m;\
    ssl_session_tickets off;\
    \
    # Modern SSL configuration\
    ssl_protocols TLSv1.2 TLSv1.3;\
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\
    ssl_prefer_server_ciphers off;\
    \
    # HSTS (included by certbot)\
    resolver 1.1.1.1 8.8.8.8 valid=300s;\
    resolver_timeout 5s;' /etc/nginx/sites-available/default
                
                nginx -t && systemctl reload nginx
            fi
            
            save_state "ssl_configured"
            
        else
            warning "Failed to obtain SSL certificate from Let's Encrypt"
            read -rp "Continue without HTTPS? (yes/no): " response
            
            if [ "$response" != "yes" ]; then
                error "User aborted due to SSL certificate failure"
            fi
            
            warning "Continuing WITHOUT SSL - connections will not be encrypted!"
            sleep 3
        fi
    fi
    
    # Verify Nginx is running
    if systemctl is-active --quiet nginx; then
        log "Nginx configured and running"
    else
        error "Nginx is not running"
    fi
}

# Create comprehensive credentials file
create_credentials() {
    section "Generating Credentials Documentation"
    
    local cred_dir="/root/vpn_credentials"
    mkdir -p "$cred_dir"
    chmod 700 "$cred_dir"
    
    local cred_file="${cred_dir}/setup_info_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$cred_file" << EOF
================================================================================
VPS SECURITY & WIREGUARD SETUP - CONFIGURATION DETAILS
================================================================================
Generated: $(date)
Script Version: ${SCRIPT_VERSION}
Hostname: ${HOST_FQDN}
Public IP: ${PUBLIC_IP}

================================================================================
SSH ACCESS INFORMATION
================================================================================
Port: ${SSH_PORT}
User: ${USER_ACCOUNT_NAME}
Authentication: SSH Key Only (password authentication disabled)
Sudo Access: Passwordless (no password required for sudo commands)
$([ -n "${USER_PASSWORD:-}" ] && echo "Account Password: (set during installation)" || echo "Account Password: (using existing password)")

IMPORTANT: 
- Root login is disabled for password authentication
- Only SSH key authentication is allowed
- User '${USER_ACCOUNT_NAME}' has sudo privileges
- Passwordless sudo is configured (no password needed for sudo commands)
- Account password is set for console access and other services

================================================================================
WIREGUARD VPN SERVER
================================================================================
Server Public Key: ${SERVER_PUBLIC_KEY}
Server Internal IP: ${WG_SERVER_IP}
Listen Port: ${WG_PORT}
Interface: wg0

Management Commands:
  Check status: systemctl status wg-quick@wg0
  View peers:   wg show
  Restart:      systemctl restart wg-quick@wg0

================================================================================
WIREGUARD CLIENT CONFIGURATIONS
================================================================================
Client configurations are stored in: /etc/wireguard/clients/

Client 1:
  - Config: /etc/wireguard/clients/client1.conf
  - QR Code: /etc/wireguard/clients/client1_qr.txt
  - Display QR: cat /etc/wireguard/clients/client1_qr.txt

To create additional clients:
  1. Generate keys: wg genkey | tee client.key | wg pubkey > client.pub
  2. Create config file with unique IP (10.10.10.3, .4, etc.)
  3. Add peer to server: wg set wg0 peer <PUBLIC_KEY> allowed-ips <IP>/32
  4. Save: wg-quick save wg0

================================================================================
WEB INTERFACE ACCESS
================================================================================
$(if [ "$ENABLE_SSL" = true ] && [ -f /etc/letsencrypt/live/${HOST_FQDN}/fullchain.pem ]; then
    echo "WireGuard Dashboard: https://${HOST_FQDN}/"
    echo "Netdata Monitoring:  https://${HOST_FQDN}/netdata/"
    echo ""
    echo "SSL Certificate: Let's Encrypt (auto-renewal configured)"
else
    echo "WireGuard Dashboard: http://${HOST_FQDN}/"
    echo "Netdata Monitoring:  http://${HOST_FQDN}/netdata/"
    echo ""
    echo "WARNING: SSL not configured - connections are NOT encrypted"
fi)

WGDashboard Credentials:
  Username: admin
  Password: admin
  ⚠️  CHANGE IMMEDIATELY ON FIRST LOGIN!

Netdata Credentials:
  Username: ${USER_ACCOUNT_NAME}
  Password: (set during installation)

================================================================================
SECURITY CONFIGURATION
================================================================================
Firewall (UFW):
  Status: Enabled
  Allowed Ports: ${SSH_PORT}/tcp, ${WG_PORT}/udp, 80/tcp, 443/tcp

Fail2Ban:
  Status: Active
  Protected Services: SSH, Nginx
  Ban Time: 3600 seconds (1 hour)
  Max Retries: 3

SSH Hardening:
  - Root password login: Disabled
  - Password authentication: Disabled
  - Key-only authentication: Enabled
  - Strong crypto algorithms: Enabled

System Hardening:
  - Automatic security updates: Enabled (daily)
  - Network stack hardening: Applied
  - SYN flood protection: Enabled
  - IP spoofing protection: Enabled

================================================================================
MAINTENANCE COMMANDS
================================================================================
View Setup Logs:
  tail -f /var/log/secure_vpn_setup.log

Check Service Status:
  systemctl status sshd
  systemctl status wg-quick@wg0
  systemctl status wgdashboard
  systemctl status netdata
  systemctl status nginx
  systemctl status fail2ban

View Firewall Rules:
  ufw status verbose
  
View Fail2Ban Status:
  fail2ban-client status
  fail2ban-client status sshd

View WireGuard Status:
  wg show
  wg show wg0

Test Nginx Configuration:
  nginx -t

View Nginx Logs:
  tail -f /var/log/nginx/access.log
  tail -f /var/log/nginx/error.log

================================================================================
BACKUP INFORMATION
================================================================================
Configuration backups stored in: ${BACKUP_DIR}
This includes original versions of modified system files.

To restore a configuration:
  cp ${BACKUP_DIR}/<backup_file> /path/to/original/location
  systemctl restart <affected_service>

================================================================================
IMPORTANT SECURITY REMINDERS
================================================================================
1. Change WGDashboard default password (admin/admin) IMMEDIATELY
2. Store WireGuard client configurations securely
3. Never share private keys
4. Keep this file in a secure location (it contains sensitive information)
5. Regularly review system logs for suspicious activity
6. Test SSH access before closing your current session
7. Consider setting up external monitoring/alerting

================================================================================
NEXT STEPS
================================================================================
1. Test SSH access with your key: ssh -p ${SSH_PORT} ${USER_ACCOUNT_NAME}@${PUBLIC_IP}
2. Access WGDashboard and change default password
3. Download client1.conf and import to WireGuard client application
4. Test VPN connection
5. Review Netdata monitoring dashboard
6. Delete this file after securely storing credentials

================================================================================
SUPPORT & DOCUMENTATION
================================================================================
WireGuard: https://www.wireguard.com/
WGDashboard: https://github.com/donaldzou/WGDashboard
Netdata: https://www.netdata.cloud/
Fail2Ban: https://www.fail2ban.org/

================================================================================
EOF

    chmod 600 "$cred_file"
    log "Credentials saved to: $cred_file"
    
    # Create a symlink to latest
    ln -sf "$cred_file" "${cred_dir}/latest.txt"
    
    echo "$cred_file"
}

# Display completion message
show_completion() {
    local cred_file="$1"
    
    cat << EOF

${GREEN}================================================================================
SETUP COMPLETED SUCCESSFULLY!
================================================================================${NC}

Your Debian VPS has been configured with:
  ✓ System security hardening
  ✓ WireGuard VPN server (port ${WG_PORT})
  ✓ WGDashboard management interface
  ✓ Netdata system monitoring
  ✓ Nginx reverse proxy$([ "$ENABLE_SSL" = true ] && echo " with SSL/TLS")
  ✓ UFW firewall + Fail2Ban
  ✓ Automatic security updates

${YELLOW}IMPORTANT - READ CAREFULLY:${NC}

1. ${RED}Test SSH access NOW in a new terminal:${NC}
   ssh -p ${SSH_PORT} ${USER_ACCOUNT_NAME}@${PUBLIC_IP}
   
   ${RED}DO NOT close this session until you verify you can log in!${NC}

2. Access WGDashboard at:
   $([ "$ENABLE_SSL" = true ] && echo "https://${HOST_FQDN}/" || echo "http://${HOST_FQDN}/")
   
   ${RED}Change default password (admin/admin) IMMEDIATELY!${NC}

3. Access Netdata monitoring at:
   $([ "$ENABLE_SSL" = true ] && echo "https://${HOST_FQDN}/netdata/" || echo "http://${HOST_FQDN}/netdata/")
   Login: ${USER_ACCOUNT_NAME}

4. WireGuard client configuration:
   ${cred_file}
   
   View QR code: ${GREEN}cat /etc/wireguard/clients/client1_qr.txt${NC}

5. ${YELLOW}Complete credentials and instructions:${NC}
   ${cred_file}
   
   ${RED}Store this file securely and delete from server when done!${NC}

${GREEN}================================================================================${NC}

${BLUE}Next Steps:${NC}
  1. Verify SSH access works with your key
  2. Change WGDashboard password
  3. Import WireGuard client configuration
  4. Test VPN connection
  5. Secure and delete credentials file

${GREEN}Thank you for using this setup script!${NC}

EOF
}

# Main execution flow
main() {
    # Pre-flight checks (before logging starts)
    check_bash_version
    check_root
    check_debian_version
    check_critical_dependencies
    
    # Initialize logging
    init_log
    
    # Load configuration
    load_config
    
    # Gather information
    test_network
    preseed_postfix_settings
    get_public_ip
    get_host_fqdn
    select_user_name
    get_user_password
    get_pubkey
    
    # System setup
    install_packages
    setup_unattended_upgrades
    harden_sysctl
    
    # Security configuration
    secure_ssh
    install_user_ssh_pubkey root /root "$SSH_PUBLIC_KEY"
    install_user_ssh_pubkey "$USER_ACCOUNT_NAME" "/home/$USER_ACCOUNT_NAME" "$SSH_PUBLIC_KEY"
    setup_firewall
    
    # VPN and monitoring
    install_wireguard
    install_wgdashboard
    
    if [ "$INSTALL_NETDATA" = true ]; then
        install_netdata
    fi
    
    # Web interface
    configure_nginx
    
    # Documentation
    local cred_file
    cred_file=$(create_credentials)
    
    # Completion
    show_completion "$cred_file"
    
    log "Setup completed successfully at $(date)"
    save_state "setup_complete"
}

# Run main function
main "$@"
