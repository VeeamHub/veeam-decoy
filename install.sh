#!/bin/bash

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/redhat-release ]]; then
        os_version=$(cat /etc/redhat-release)
        if [[ $os_version =~ [0-9]+\.[0-9]+ ]]; then
            version="${BASH_REMATCH[0]}"
            major_version=${version%.*}
            minor_version=${version#*.}
            
            if [[ $major_version -eq 9 && $minor_version -ge 3 ]] || [[ $major_version -gt 9 ]]; then
                echo "Compatible Rocky Linux version detected: $version"
                return 0
            else
                echo "This script requires Rocky Linux 9.3 or higher"
                echo "Current system: $os_version"
                exit 1
            fi
        else
            echo "Failed to extract version number"
            exit 1
        fi
    else
        echo "Unable to determine the operating system version"
        exit 1
    fi
}

check_disable_selinux_firewall() {
    echo "Checking SELinux and firewall status..."
    selinux_status=$(getenforce)
    if [ "$selinux_status" != "Disabled" ]; then
        echo "Error: SELinux is not disabled. Current status: $selinux_status"
        echo "Disabling SELinux..."
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        echo "SELinux has been disabled in the configuration. A reboot is required for this change to take effect."
    fi
    firewall_active=$(systemctl is-active firewalld)
    firewall_enabled=$(systemctl is-enabled firewalld)
    if [ "$firewall_active" = "active" ] || [ "$firewall_enabled" = "enabled" ]; then
        echo "Firewall is active or enabled. Disabling and stopping firewall..."
        systemctl stop firewalld && systemctl disable firewalld
        echo "Firewall has been stopped and disabled."
    fi
    echo "SELinux and firewall checks completed. Proceeding with installation."
}

install_basic_dependencies() {
    echo "Installing basic dependencies..."
    dnf update -y
    dnf install -y git python3 python3-pip nano wget libpcap bc
}

clone_repo() {
    echo "Cloning the repository..."
    if [ -d "/tmp/decoys" ]; then
        echo "Removing existing /tmp/decoys directory..."
        rm -rf /tmp/decoys
    fi
    git clone https://github.com/VeeamHub/veeam-decoy.git /tmp/decoys
    rm -f /tmp/decoys/install.sh
    rm -rf /tmp/decoys/.git
    echo "Repository cloned successfully and install.sh removed"
}

install_python_dependencies() {
    echo "Installing Python dependencies..."
    if [ -f /tmp/decoys/requirements.txt ]; then
        echo "Installing dependencies from requirements.txt..."
        pip3 install -r /tmp/decoys/requirements.txt
    else
        echo "requirements.txt file not found. Skipping Python dependencies installation."
    fi
}

create_directories() {
    echo "Creating directories..."
    mkdir -p /opt/NETB /opt/NETW /opt/RDP /opt/SSH /opt/TUI /opt/VBEM /opt/VBR /opt/VHR /opt/VWR
    mkdir -p /etc/hnp
}

copy_files() {
    echo "Copying files..."
    cp /tmp/decoys/NETB/* /opt/NETB/
    cp /tmp/decoys/NETW/* /opt/NETW/
    cp /tmp/decoys/RDP/* /opt/RDP/
    cp /tmp/decoys/SSH/* /opt/SSH/
    cp /tmp/decoys/TUI/* /opt/TUI/
    cp /tmp/decoys/VBEM/* /opt/VBEM/
    cp /tmp/decoys/VBR/* /opt/VBR/
    cp /tmp/decoys/VHR/* /opt/VHR/
    cp /tmp/decoys/VWR/* /opt/VWR/
    cp /tmp/decoys/etc/hnp/* /etc/hnp/
    cp /tmp/decoys/etc/rsyslog.d/* /etc/rsyslog.d/
    if [ -f /tmp/decoys/etc/sshd/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        cp /tmp/decoys/etc/sshd/sshd_config /etc/ssh/
        echo "A backup of the original sshd_config file has been created at /etc/ssh/sshd_config.backup"
    else
        echo "sshd_config file not found in the repository. Keeping the existing file."
    fi
    if [ -f /tmp/decoys/etc/profile ]; then
        profile_line="/usr/local/bin/start_hnp_tui.sh"
        if ! grep -qF "$profile_line" /etc/profile; then
            echo "Adding the following line to /etc/profile:"
            echo "$profile_line"
            echo "$profile_line" >> /etc/profile
        else
            echo "The line already exists in /etc/profile. No changes made."
        fi
    else
        echo "Profile file not found in the repository. No changes made to /etc/profile."
    fi
    cp /tmp/decoys/*.service /etc/systemd/system/
    cp /tmp/decoys/usr/local/bin/start_hnp_tui.sh /usr/local/bin/
}

set_permissions() {
    echo "Setting permissions..."
    chmod +x /opt/NETB/netbios_honeypot.py
    chmod +x /opt/NETW/network_config.py
    chmod +x /opt/RDP/rdp_honeypot.py
    chmod +x /opt/SSH/ssh_honeypot.py
    chmod +x /opt/TUI/hnp_tui.py
    chmod +x /opt/VBEM/vbem_server.py
    chmod +x /opt/VBR/vbr_server.py
    chmod +x /opt/VHR/vhr_honeypot.py
    chmod +x /opt/VWR/vwr_honeypot.py
    chmod +x /usr/local/bin/start_hnp_tui.sh
}

start_services() {
    echo "Starting services..."
    systemctl daemon-reload
    for service in /etc/systemd/system/*-honeypot.service; do
        systemctl start $(basename $service)
    done
    systemctl restart rsyslog
    systemctl restart sshd
}

cleanup() {
    echo "Cleaning up temporary files..."
    rm -rf /tmp/decoys
}

main() {
    check_root
    check_os
    check_disable_selinux_firewall
    install_basic_dependencies
    clone_repo
    install_python_dependencies
    create_directories
    copy_files
    set_permissions
    start_services
    cleanup
    echo "Installation completed successfully"
    echo "It is recommended to restart the system to apply all changes, especially for SELinux configuration"
}

main
