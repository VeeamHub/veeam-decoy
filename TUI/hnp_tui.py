#!/usr/bin/env python3
import curses
import subprocess
import os
import logging
import logging.handlers
import gzip
import shutil
from datetime import datetime
import sys
import threading
import time
import psutil
import select
import fcntl
import configparser
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import smtplib


class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S.%fZ')
        return f"<{record.levelno}>1 {timestamp} {os.uname().nodename} hnpTUI {os.getpid()} - - {record.getMessage()}"

class CompressedTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def __init__(self, filename, when='midnight', interval=1, backupCount=30, encoding=None, delay=False, utc=False, atTime=None):
        super().__init__(filename, when, interval, backupCount, encoding, delay, utc, atTime)

    def rotator(self, source, dest):
        with open(source, 'rb') as f_in:
            with gzip.open(f'{dest}.gz', 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(source)

    def doRollover(self):
        super().doRollover()
        with open(self.baseFilename, 'w'):
            pass

def setup_logging():
    log_dir = '/var/log/hnp'
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("hnpTUI")
    logger.setLevel(logging.INFO)
    handler = CompressedTimedRotatingFileHandler(
        os.path.join(log_dir, 'hnp_tui.log'),
        when="midnight",
        interval=1,
        backupCount=30
    )
    handler.setFormatter(RFC5424Formatter())
    logger.addHandler(handler)
    return logger

logger = setup_logging()

def run_command(command):
    logger.info(f"Executing command: {command}")
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    logger.info(f"Command result: {result.stdout.strip()}")
    return result.stdout.strip(), result.returncode

def get_service_status(service_name):
    status, _ = run_command(f"systemctl is-active {service_name}")
    if status == "active":
        return "Active"
    elif status == "inactive":
        return "Stopped"
    else:
        return "Failed"

def get_service_boot_status(service_name):
    status, _ = run_command(f"systemctl is-enabled {service_name}")
    return "Yes" if status.strip() == "enabled" else "No"

def toggle_service(service_name, action):
    command = f"systemctl {action} {service_name}"
    _, return_code = run_command(command)
    return return_code == 0

def toggle_service_boot(service_name):
    current_status = get_service_boot_status(service_name)
    action = "disable" if current_status == "Yes" else "enable"
    _, return_code = run_command(f"sudo systemctl {action} {service_name}")
    return return_code == 0

def get_network_info():
    interfaces, _ = run_command("ip -o addr show")
    routes, _ = run_command("ip route show default")
    return [intf for intf in interfaces.split('\n') if not intf.startswith('1: lo')], routes.split('\n')

def edit_config_file(file_path):
    curses.endwin()
    os.system(f"sudo nano {file_path}")
    return curses.initscr()

def get_used_ports_and_interfaces():
    used_ports = set()
    used_interfaces = set()
    net_if_addrs = psutil.net_if_addrs()

    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr:
            used_ports.add(conn.laddr.port)
            ip = conn.laddr.ip
            if ip != '::' and ip != '0.0.0.0':
                for interface, addrs in net_if_addrs.items():
                    for addr in addrs:
                        if addr.address == ip and interface != 'lo':
                            used_interfaces.add(interface)
                            break

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            used_ports.add(conn.laddr.port)

    return sorted(used_ports), sorted(used_interfaces)

def get_last_log_line(service_name):
    log_file = f"/var/log/hnp/{service_name}"
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                parts = last_line.split("- - -")
                if len(parts) > 1:
                    return parts[-1].strip()
                return last_line
    return "No log available"

class SystemManagementTUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.services = [
            ("vbr-honeypot", "Veeam Backup Server"),
            ("vhr-honeypot", "Veeam Hardened Repository"),
            ("vwr-honeypot", "Veeam Windows Repository"),
            ("vbem-honeypot", "Enterprise Manager"),
            ("rdp-honeypot", "Remote Desktop Service"),
            ("ssh-honeypot", "SSH Decoy"),
            ("netbios-honeypot", "Netbios Service"),
            ("rsyslog", "Rsyslog Service"),
            ("sshd", "SSH Admin port:41325")
        ]
        self.service_statuses = {}
        self.boot_statuses = {}
        self.used_ports = []
        self.used_interfaces = []
        curses.curs_set(0)
        self.height, self.width = self.stdscr.getmaxyx()
        self.current_option = 0
        self.options = []
        self.last_update = 0
        logger.info("hnpTUI initialized")
        self.start_service_monitor()
        self.update_service_statuses()

    def start_service_monitor(self):
        def monitor_services():
            while True:
                self.update_service_statuses()
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=monitor_services, daemon=True)
        self.monitor_thread.start()

    def update_service_statuses(self):
        new_statuses = {}
        new_boot_statuses = {}
        for service, _ in self.services:
            new_statuses[service] = get_service_status(service)
            new_boot_statuses[service] = get_service_boot_status(service)

        if new_statuses != self.service_statuses or new_boot_statuses != self.boot_statuses:
            self.service_statuses = new_statuses
            self.boot_statuses = new_boot_statuses
            self.used_ports, self.used_interfaces = get_used_ports_and_interfaces()
            self.draw_menu()

    def safe_addstr(self, y, x, string, attr=curses.A_NORMAL):
        try:
            self.stdscr.addstr(y, x, string, attr)
        except curses.error:
            pass

    def draw_box(self, y, x, h, w):
        self.safe_addstr(y, x, '+' + '-' * (w-2) + '+')
        for i in range(1, h-1):
            self.safe_addstr(y+i, x, '|' + ' ' * (w-2) + '|')
        self.safe_addstr(y+h-1, x, '+' + '-' * (w-2) + '+')

    def clean_interface_info(self, info):
        parts = info.split()
        if len(parts) >= 4:
            return f"{parts[1]} {parts[3]}"
        return info

    def draw_menu(self):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        self.options = []

        self.draw_box(0, 0, h-1, w)

        header = f"Decoy System Management | {os.uname().nodename} | {os.uname().sysname} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.safe_addstr(1, 2, header.center(w-4), curses.A_BOLD)
        self.safe_addstr(2, 1, '-' * (w-2))

        services_box_height = len(self.services) + 7
        self.draw_box(3, 1, services_box_height, w//2-1)
        self.safe_addstr(3, 2, " Decoy Services ", curses.A_BOLD)
        for idx, (service, display_name) in enumerate(self.services):
            status = self.service_statuses.get(service, "Unknown")
            boot_status = self.boot_statuses.get(service, "Unknown")
            self.safe_addstr(5+idx, 3, f"{display_name:<25} {status:<8}")
            button_start_x = 37
            for action in ["Start", "Restart", "Stop"]:
                option = (5+idx, button_start_x, f"[{action}]", f"{service},{action.lower()}")
                self.options.append(option)
                self.safe_addstr(*option[:3])
                button_start_x += len(action) + 3
            boot_option = (5+idx, button_start_x, f"[Boot: {boot_status:3}]", f"{service},toggle_boot")
            self.options.append(boot_option)
            self.safe_addstr(*boot_option[:3])

        self.draw_box(3, w//2, services_box_height, w//2-1)
        self.safe_addstr(3, w//2+1, " Network Interfaces ", curses.A_BOLD)
        option = (5, w//2+2, "[Config Network]", "config_network")
        self.options.append(option)
        self.safe_addstr(*option[:3])
        self.safe_addstr(6, w//2+2, "")
        interfaces, routes = get_network_info()
        for idx, info in enumerate(interfaces[:services_box_height-11]):
            cleaned_info = self.clean_interface_info(info)
            self.safe_addstr(7+idx, w//2+2, cleaned_info[:w//2-6])
        self.safe_addstr(services_box_height-5, w//2+2, "Default Routes:")
        default_routes = [route for route in routes if route.startswith("default")]
        for idx, route in enumerate(default_routes):
            if services_box_height-4+idx < services_box_height:
                self.safe_addstr(services_box_height-4+idx, w//2+2, route[:w//2-6])

        config_box_height = 9
        self.draw_box(services_box_height + 3, 1, config_box_height, w//2-1)
        self.safe_addstr(services_box_height + 3, 2, " Config Files ", curses.A_BOLD)
        config_files = [
            ("/etc/hnp/config", "Decoy Config File"),
            ("/etc/rsyslog.d/10-vbr.conf", "Rsyslog Decoy Config"),
            ("/etc/hosts", "Hosts File"),
            ("/etc/resolv.conf", "DNS Resolver Config"),
            ("/etc/iproute2/rt_tables", "Routing Tables Config")
        ]
        for idx, (file, description) in enumerate(config_files):
            option = (services_box_height + 5 + idx, 3, f"[Edit] {file:<30} {description}", f"edit_{idx}")
            self.options.append(option)
            self.safe_addstr(*option[:3])

        self.draw_box(services_box_height + 3, w//2, config_box_height, w//2-1)
        self.safe_addstr(services_box_height + 3, w//2+1, " Settings ", curses.A_BOLD)
        option = (services_box_height + 5, w//2+2, "[Change Password]", "change_password")
        self.options.append(option)
        self.safe_addstr(*option[:3])
        option = (services_box_height + 6, w//2+2, "[Test Email]", "test_email")
        self.options.append(option)
        self.safe_addstr(*option[:3])

        ports_box_height = 19
        ports_box_width = w//2 - 1
        self.draw_box(services_box_height + config_box_height + 3, 1, ports_box_height, ports_box_width)
        self.safe_addstr(services_box_height + config_box_height + 3, 2, " Ports and Interfaces in Use ", curses.A_BOLD)

        self.safe_addstr(services_box_height + config_box_height + 5, 3, "Used ports:")
        ports_per_line = (ports_box_width - 6) // 6
        y = services_box_height + config_box_height + 6
        for i, port in enumerate(self.used_ports):
            y = services_box_height + config_box_height + 6 + i // ports_per_line
            x = 3 + (i % ports_per_line) * 6
            if y < services_box_height + config_box_height + ports_box_height - 2:
                self.safe_addstr(y, x, f"{port:5}")
            else:
                self.safe_addstr(y - 1, ports_box_width - 15, "... more ports")
                break

        interfaces_y = min(y + 2, services_box_height + config_box_height + ports_box_height - 4)
        self.safe_addstr(interfaces_y, 3, "Used interfaces:")
        interfaces_str = ", ".join(self.used_interfaces)
        wrapped_interfaces = [interfaces_str[i:i+ports_box_width-5] for i in range(0, len(interfaces_str), ports_box_width-5)]
        for i, line in enumerate(wrapped_interfaces):
            if interfaces_y + i + 1 < services_box_height + config_box_height + ports_box_height - 1:
                self.safe_addstr(interfaces_y + i + 1, 3, line)

        last_log_box_height = 19
        self.draw_box(services_box_height + config_box_height + 3, w//2, last_log_box_height, w//2-1)
        self.safe_addstr(services_box_height + config_box_height + 3, w//2+1, " Last Log Lines ", curses.A_BOLD)
        log_files = {
            "vbr-honeypot": "vbr_honeypot.log",
            "vhr-honeypot": "vhr_honeypot.log",
            "vwr-honeypot": "vwr_honeypot.log",
            "vbem-honeypot": "vbem_honeypot.log",
            "rdp-honeypot": "rdp_honeypot.log",
            "ssh-honeypot": "ssh_honeypot.log",
            "netbios-honeypot": "netbios_honeypot.log"
        }
        for idx, (service, log_file) in enumerate(log_files.items()):
            if idx * 2 + 2 < last_log_box_height - 3:
                display_name = next(name for s, name in self.services if s == service)
                log_line = get_last_log_line(log_file)
                self.safe_addstr(services_box_height + config_box_height + 5 + idx*2, w//2+2, f"{display_name}:")
                wrapped_log = [log_line[i:i+w//2-8] for i in range(0, len(log_line), w//2-8)]
                for j, line in enumerate(wrapped_log[:1]):
                    self.safe_addstr(services_box_height + config_box_height + 6 + idx*2 + j, w//2+2, line)

        self.safe_addstr(h-2, 1, '-' * (w-2))
        footer_text = "Tab/Arrows: Navigate | Enter: Select | Q: Quit | C: Console | R: Reboot | P: Poweroff"
        self.safe_addstr(h-1, 2, footer_text, curses.A_BOLD)

        self.highlight_option()
        self.stdscr.refresh()

    def highlight_option(self):
        if self.options and 0 <= self.current_option < len(self.options):
            y, x, text, _ = self.options[self.current_option]
            self.safe_addstr(y, x, text, curses.A_REVERSE)
        else:
            self.current_option = 0

    def run(self):
        logger.info("hnpTUI started")
        while True:
            self.draw_menu()
            key = self.stdscr.getch()
            if not self.handle_key(key):
                break

            if time.time() - self.last_update >= 1:
                self.update_service_statuses()
                self.last_update = time.time()

        logger.info("hnpTUI stopped")

    def handle_key(self, key):
        if key == ord('q') or key == ord('Q'):
            return False
        elif key == ord('c') or key == ord('C'):
            self.open_console()
        elif key == ord('r') or key == ord('R'):
            self.reboot_server()
        elif key == ord('p') or key == ord('P'):
            self.poweroff_server()
        elif key in [ord('\t'), curses.KEY_DOWN, curses.KEY_RIGHT]:
            self.current_option = (self.current_option + 1) % len(self.options)
        elif key in [curses.KEY_UP, curses.KEY_LEFT]:
            self.current_option = (self.current_option - 1) % len(self.options)
        elif key == 10:
            self.execute_option()
        return True

    def execute_option(self):
        _, _, _, action = self.options[self.current_option]
        if "," in action:
            service, act = action.split(",")
            if act == "toggle_boot":
                self.toggle_service_boot(service)
            else:
                self.manage_service(service, act)
        elif action == "config_network":
            self.config_network()
        elif action.startswith("edit_"):
            idx = int(action.split("_")[1])
            self.edit_config_file(["/etc/hnp/config", "/etc/rsyslog.d/10-vbr.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/iproute2/rt_tables"][idx])
        elif action == "change_password":
            self.change_password()
        elif action == "test_email":
            self.test_email_configuration()

    def create_popup(self, message, height=7, width=60):
        h, w = self.stdscr.getmaxyx()
        popup_h, popup_w = height, min(max(width, len(message) + 4), w - 4)
        popup_y, popup_x = (h - popup_h) // 2, (w - popup_w) // 2
        popup = curses.newwin(popup_h, popup_w, popup_y, popup_x)
        popup.box()
        wrapped_message = [message[i:i+popup_w-4] for i in range(0, len(message), popup_w-4)]
        for i, line in enumerate(wrapped_message[:popup_h-4]):
            popup.addstr(i+2, 2, line)
        popup.refresh()
        return popup

    def update_popup(self, popup, message):
        popup.clear()
        popup.box()
        h, w = popup.getmaxyx()
        wrapped_message = [message[i:i+w-4] for i in range(0, len(message), w-4)]
        for i, line in enumerate(wrapped_message[:h-2]):
            popup.addstr(i+1, 2, line)
        popup.refresh()

    def test_email_configuration(self):
        popup = self.create_popup("Testing email configuration...", height=10, width=70)
        logger.info("Starting email configuration test")
        try:
            logger.info("Reading email configuration from /etc/hnp/config")
            config = configparser.ConfigParser()
            config.read('/etc/hnp/config')
            
            if 'Email' not in config:
                error_msg = "Email configuration section not found in /etc/hnp/config"
                logger.error(error_msg)
                logger.error("Available sections in config: " + ", ".join(config.sections()))
                self.update_popup(popup, f"Error: {error_msg}\n\nPress any key to continue...")
                popup.getch()
                return

            email_config = config['Email']
            logger.info(f"Email Configuration Details:")
            logger.info(f"- SMTP Server: {email_config.get('smtp_server', 'Not configured')}")
            logger.info(f"- SMTP Port: {email_config.get('smtp_port', 'Not configured')}")
            logger.info(f"- From Email: {email_config.get('from_email', 'Not configured')}")
            logger.info(f"- To Email: {email_config.get('to_email', 'Not configured')}")
            logger.info(f"- Enabled: {email_config.get('Enabled', 'No')}")
            
            if email_config.get('Enabled', 'No').lower() != 'yes':
                error_msg = "Email is disabled in configuration"
                logger.error(error_msg)
                self.update_popup(popup, f"Error: {error_msg}. Please enable it first.\n\nPress any key to continue...")
                popup.getch()
                return

            required_fields = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password', 'from_email', 'to_email']
            missing_fields = [field for field in required_fields if not email_config.get(field)]
            
            if missing_fields:
                error_msg = "Missing required email configuration fields: " + ", ".join(missing_fields)
                logger.error(error_msg)
                self.update_popup(popup, f"Error: {error_msg}\n\nPress any key to continue...")
                popup.getch()
                return

            logger.info("Preparing email message")
            self.update_popup(popup, "Preparing test email...")
            
            msg = MIMEMultipart()
            from_name = email_config.get('from_name', 'HNP System')
            formatted_from = formataddr((from_name, email_config['from_email']))
            msg['From'] = formatted_from
            msg['To'] = email_config['to_email']
            msg['Subject'] = f"Test Email from HNP System - {socket.gethostname()}"
            
            logger.info(f"Email headers prepared:")
            logger.info(f"- From: {formatted_from}")
            logger.info(f"- To: {email_config['to_email']}")
            logger.info(f"- Subject: {msg['Subject']}")
            
            body = "This is a test email from your HNP (Honeypot) System.\n\n"
            body += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            body += f"Host: {socket.gethostname()}\n"
            body += "\nIf you received this email, your email configuration is working correctly."
            
            msg.attach(MIMEText(body, 'plain'))

            # Conexión SMTP
            logger.info(f"Attempting to connect to SMTP server {email_config['smtp_server']}:{email_config['smtp_port']}")
            self.update_popup(popup, "Connecting to SMTP server...")
            try:
                server = smtplib.SMTP(email_config['smtp_server'], int(email_config['smtp_port']))
                logger.info("SMTP connection established")
            except (smtplib.SMTPConnectError, ConnectionRefusedError) as e:
                logger.error(f"Failed to connect to SMTP server: {str(e)}")
                raise

            # TLS
            logger.info("Starting TLS connection")
            self.update_popup(popup, "Establishing secure connection...")
            try:
                server.starttls()
                logger.info("TLS connection established")
            except Exception as e:
                logger.error(f"Failed to start TLS: {str(e)}")
                raise

            # Login
            logger.info(f"Attempting to login with username: {email_config['smtp_username']}")
            self.update_popup(popup, "Authenticating...")
            try:
                server.login(email_config['smtp_username'], email_config['smtp_password'])
                logger.info("SMTP authentication successful")
            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"Authentication failed: {str(e)}")
                raise
            
            # Envío
            logger.info("Sending email message")
            self.update_popup(popup, "Sending test email...")
            try:
                server.send_message(msg)
                logger.info("Email sent successfully")
            except Exception as e:
                logger.error(f"Failed to send message: {str(e)}")
                raise
            finally:
                logger.info("Closing SMTP connection")
                server.quit()

            success_msg = (
                "Test email sent successfully!\n\n"
                f"Recipient: {email_config['to_email']}\n\n"
                "Please check your inbox.\n\n"
                "Press any key to continue..."
            )
            self.update_popup(popup, success_msg)
            popup.getch()

        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            
            logger.error(f"Email test failed with {error_type}: {error_msg}")
            logger.error("Full error traceback:", exc_info=True)
            
            user_msg = "Failed to send test email:\n\n"
            if isinstance(e, smtplib.SMTPAuthenticationError):
                user_msg += "Authentication failed. Please check your username and password."
            elif isinstance(e, (smtplib.SMTPConnectError, ConnectionRefusedError)):
                user_msg += "Could not connect to SMTP server. Please check server address and port."
            elif isinstance(e, smtplib.SMTPException):
                user_msg += f"SMTP Error: {error_msg}"
            else:
                user_msg += f"Unexpected error: {error_msg}"
            
            user_msg += "\n\nPlease check your email configuration in /etc/hnp/config"
            user_msg += "\nCheck /var/log/hnp/hnp_tui.log for detailed error information"
            user_msg += "\n\nPress any key to continue..."
            
            logger.info("Email test completed with errors")
            self.update_popup(popup, user_msg)
            popup.getch()
        else:
            logger.info("Email test completed successfully")

        self.stdscr.clear()
        self.draw_menu()

    def manage_service(self, service, action):
        popup_msg = f"{action.capitalize()}ing {service}..."
        popup = self.create_popup(popup_msg)
        success = toggle_service(service, action)
        if success:
            for i in range(20):
                new_status = get_service_status(service)
                self.update_popup(popup, f"{service} status: {new_status}")
                if (action == "start" and new_status == "Active") or \
                   (action == "stop" and new_status == "Stopped") or \
                   (action == "restart" and new_status == "Active"):
                    break
                time.sleep(0.1)
            self.update_popup(popup, f"{service} is now {new_status}")
        else:
            logger.error(f"Failed to {action} {service}")
            self.update_popup(popup, "Failed. Review Logs")
        time.sleep(2)
        self.used_ports, self.used_interfaces = get_used_ports_and_interfaces()
        self.update_service_statuses()
        self.stdscr.clear()
        self.draw_menu()

    def toggle_service_boot(self, service):
        popup_msg = f"Toggling boot status for {service}..."
        popup = self.create_popup(popup_msg)
        success = toggle_service_boot(service)
        if success:
            new_status = get_service_boot_status(service)
            self.update_popup(popup, f"Boot status for {service} is now: {new_status}")
        else:
            logger.error(f"Failed to toggle boot status for {service}")
            self.update_popup(popup, "Failed. Review Logs")
        time.sleep(2)
        self.update_service_statuses()
        self.stdscr.clear()
        self.draw_menu()

    def change_password(self):
        def get_password(window, prompt):
            window.addstr(2, 2, prompt)
            window.refresh()
            password = ""
            while True:
                ch = window.getch()
                if ch == 10:
                    break
                elif ch == 27:
                    return None
                elif ch == 127 or ch == 263:
                    if password:
                        password = password[:-1]
                        window.addstr(3, 2, " " * (len(password) + 1))
                elif ch < 256:
                    password += chr(ch)
                window.addstr(3, 2, "*" * len(password))
                window.refresh()
            return password

        popup = self.create_popup("Change root password", height=9, width=60)
        new_password = get_password(popup, "Enter new root password:")
        if new_password is None:
            self.show_message("Password change cancelled")
            return

        popup.clear()
        popup.box()
        confirm_password = get_password(popup, "Confirm new root password:")
        if confirm_password is None:
            self.show_message("Password change cancelled")
            return

        if new_password == confirm_password:
            process = subprocess.Popen(['passwd', 'root'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(input=f"{new_password}\n{new_password}\n".encode())
            if process.returncode == 0:
                self.show_message("Password changed successfully")
            else:
                self.show_message(f"Failed to change password: {stderr.decode()}")
        else:
            self.show_message("Passwords do not match")

    def config_network(self):
        h, w = self.stdscr.getmaxyx()
        popup = curses.newwin(h-4, w-4, 2, 2)
        popup.box()
        popup.addstr(1, 2, "Network Configuration", curses.A_BOLD)
        popup.refresh()

        script_path = "/opt/NETW/network_config.py"

        if not os.path.exists(script_path):
            popup.addstr(3, 2, f"Error: Script not found at {script_path}")
            popup.addstr(5, 2, "Press any key to continue...")
            popup.refresh()
            popup.getch()
            return

        if os.environ.get('DISPLAY'):
            cmd = f"xterm -e 'python3 {script_path}; read -p \"Press Enter to close...\"'"
        else:
            cmd = f"sudo python3 {script_path}; read -p 'Press Enter to close...'"

        popup.addstr(3, 2, "Launching network configuration in a new terminal...")
        popup.addstr(5, 2, "Please switch to the new terminal to configure the network.")
        popup.addstr(7, 2, "This window will wait until the configuration is complete.")
        popup.addstr(9, 2, "Press any key to launch the configuration...")
        popup.refresh()
        popup.getch()

        curses.endwin()
        os.system(cmd)
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)

        popup.clear()
        popup.box()
        popup.addstr(1, 2, "Network Configuration", curses.A_BOLD)
        popup.addstr(3, 2, "Network configuration completed.")
        popup.addstr(5, 2, "Press any key to continue...")
        popup.refresh()
        popup.getch()

        self.stdscr.clear()
        self.draw_menu()

    def edit_config_file(self, file_path):
        self.stdscr = edit_config_file(file_path)
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        self.draw_menu()

    def open_console(self):
        curses.endwin()
        os.system('clear')
        print("Console mode. Type 'exit' to return to hnpTUI.")

        console_log_file = '/var/log/hnp/console_commands.log'
        console_logger = logging.getLogger("ConsoleLogger")
        console_logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(console_log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        console_logger.addHandler(file_handler)

        history_file = '/tmp/hnptui_bash_history'
        open(history_file, 'a').close()

        env = os.environ.copy()
        env['HISTFILE'] = history_file
        env['HISTFILESIZE'] = '5000'
        env['HISTSIZE'] = '5000'
        env['PROMPT_COMMAND'] = f'history -a; if [ -f {history_file} ] && [ -s {history_file} ]; then echo "$(date "+%Y-%m-%d %H:%M:%S") - $(tail -n1 {history_file})" >> {console_log_file}; fi'

        try:
            subprocess.run(['/bin/bash'], env=env)
        finally:
            if os.path.exists(history_file):
                os.remove(history_file)

        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)

    def reboot_server(self):
        if self.confirm_action("Are you sure you want to reboot the server?"):
            run_command("sudo reboot")

    def poweroff_server(self):
        if self.confirm_action("Are you sure you want to power off the server?"):
            run_command("sudo poweroff")

    def confirm_action(self, message):
        popup = self.create_popup(message + "\n\nY: Yes | N: No")
        while True:
            key = popup.getch()
            if key in [ord('y'), ord('Y')]:
                return True
            elif key in [ord('n'), ord('N')]:
                return False

    def show_message(self, message):
        popup = self.create_popup(message)
        popup.getch()

def run_non_interactive():
    logger.info("Running in non-interactive mode")
    print("hnpTUI is running in non-interactive mode.")
    print("Services status:")
    services = ["vbr-honeypot", "vhr-honeypot", "vwr-honeypot", "vbem-honeypot", "rdp-honeypot", "ssh-honeypot", "netbios-honeypot", "rsyslog", "sshd"]
    for service in services:
        status = get_service_status(service)
        boot_status = get_service_boot_status(service)
        print(f"{service}: Status - {status}, Boot - {boot_status}")
    print("\nNetwork configuration:")
    interfaces, routes = get_network_info()
    for intf in interfaces:
        print(intf)
    print("\nDefault Routes:")
    for route in routes:
        print(route)
    print("\nPorts and Interfaces in use:")
    ports, used_interfaces = get_used_ports_and_interfaces()
    print(f"Used ports: {', '.join(map(str, ports))}")
    print(f"Used interfaces: {', '.join(used_interfaces)}")
    print("\nLast log lines:")
    log_files = {
        "vbr-honeypot": "vbr_honeypot.log",
        "vhr-honeypot": "vhr_honeypot.log",
        "vwr-honeypot": "vwr_honeypot.log",
        "vbem-honeypot": "vbem_honeypot.log",
        "rdp-honeypot": "rdp_honeypot.log",
        "ssh-honeypot": "ssh_honeypot.log",
        "netbios-honeypot": "netbios_honeypot.log"
    }
    for service, log_file in log_files.items():
        log_line = get_last_log_line(log_file)
        print(f"{service}: {log_line}")

def main(stdscr):
    tui = SystemManagementTUI(stdscr)
    tui.run()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root.")
        logger.error("Attempt to run script without root privileges")
        exit(1)

    if sys.stdin.isatty():
        logger.info("Running in interactive mode")
        curses.wrapper(main)
    else:
        run_non_interactive()