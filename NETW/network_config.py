import subprocess
import ipaddress
import os
import logging
from datetime import datetime

LOG_FILE = "/var/log/hnp/netw_config.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_message(message):
    print(message)
    logging.info(message)

def log_error(message):
    print(f"ERROR: {message}")
    logging.error(message)

def check_root():
    if os.geteuid() != 0:
        log_error("This script must be run as root")
        exit(1)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def list_interfaces():
    log_message("Available network interfaces:")
    result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    interfaces = [line.split()[1].strip(':') for line in result.stdout.splitlines() if not line.startswith('1: lo')]
    for interface in interfaces:
        print(interface)
    return interfaces

def configure_interface_and_routes(interface, ip_address, gateway, network):
    log_message(f"Configuring interface {interface}...")
    table_name = f"{interface}_table"
    table_number = 200 + len(subprocess.run(["ip", "route", "list", "table", "all"], capture_output=True, text=True).stdout.splitlines())

    
    connection = subprocess.run(["nmcli", "-g", "NAME,DEVICE", "connection", "show"], capture_output=True, text=True).stdout
    connection = next((line.split(':')[0] for line in connection.splitlines() if line.endswith(f":{interface}")), None)
    
    if not connection:
        connection = f"{interface}-con"
        subprocess.run(["nmcli", "connection", "add", "type", "ethernet", "con-name", connection, "ifname", interface])

    subprocess.run([
        "nmcli", "connection", "modify", connection,
        "ipv4.addresses", f"{ip_address}/24",
        "ipv4.gateway", gateway,
        "ipv4.method", "manual",
        "ipv4.route-metric", str(table_number),
        "+ipv4.routes", f"{network}/24 {gateway}",
        "+ipv4.routing-rules", f"priority 100 from {ip_address} table {table_number}",
        "+ipv4.routing-rules", f"priority 101 to {ip_address} table {table_number}"
    ])

    
    with open("/etc/iproute2/rt_tables", "a+") as f:
        f.seek(0)
        if not any(table_name in line for line in f):
            f.write(f"{table_number} {table_name}\n")

    
    subprocess.run(["nmcli", "connection", "up", connection])

    
    subprocess.run(["ip", "route", "add", f"{network}/24", "dev", interface, "src", ip_address, "table", table_name])
    subprocess.run(["ip", "route", "add", "default", "via", gateway, "dev", interface, "table", table_name])
    subprocess.run(["ip", "rule", "add", "from", ip_address, "lookup", table_name])
    subprocess.run(["ip", "rule", "add", "to", ip_address, "lookup", table_name])

    
    with open(f"/etc/NetworkManager/dispatcher.d/99-custom-routes-{interface}", "w") as f:
        f.write(f"""#!/bin/bash
if [ "$2" = "up" ] && [ "$1" = "{interface}" ]; then
    ip route add {network}/24 dev {interface} src {ip_address} table {table_name}
    ip route add default via {gateway} dev {interface} table {table_name}
    ip rule add from {ip_address} lookup {table_name}
    ip rule add to {ip_address} lookup {table_name}
fi
""")
    os.chmod(f"/etc/NetworkManager/dispatcher.d/99-custom-routes-{interface}", 0o755)

    log_message(f"Configuration completed for {interface}")

def configure_interface():
    interfaces = list_interfaces()
    interface = input("Which interface do you want to configure? Enter the name: ")
    if interface not in interfaces:
        log_error(f"The interface {interface} does not exist.")
        return

    while True:
        ip_address = input(f"Enter IP address for {interface}: ")
        if validate_ip(ip_address):
            break
        log_error("Invalid IP address. Please try again.")

    while True:
        gateway = input(f"Enter gateway address for {interface}: ")
        if validate_ip(gateway):
            break
        log_error("Invalid gateway address. Please try again.")

    while True:
        network = input(f"Enter network address for {interface} (e.g., 192.168.1.0): ")
        if validate_ip(network):
            break
        log_error("Invalid network address. Please try again.")

    configure_interface_and_routes(interface, ip_address, gateway, network)

def show_network_status():
    log_message("Current network status:")
    log_message("------------------------")
    log_message("Interfaces and IP addresses:")
    subprocess.run(["ip", "-br", "addr", "show"])
    print()
    log_message("Routing table:")
    subprocess.run(["ip", "route", "show"])
    print()
    log_message("Routing rules:")
    subprocess.run(["ip", "rule", "show"])
    print()
    log_message("Custom routing tables:")
    with open("/etc/iproute2/rt_tables", "r") as f:
        for line in f:
            if not line.startswith("#"):
                table = line.split()[1]
                log_message(f"Table {table}:")
                subprocess.run(["ip", "route", "show", "table", table])
                print()

def main_menu():
    while True:
        print("\nMain Menu:")
        print("1. List available interfaces")
        print("2. Configure an interface")
        print("3. Show current network status")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            list_interfaces()
        elif choice == '2':
            configure_interface()
        elif choice == '3':
            show_network_status()
        elif choice == '4':
            log_message("Exiting the script.")
            break
        else:
            log_error("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    log_message("Starting network configuration script")
    check_root()
    main_menu()
    log_message("Network configuration script completed")
