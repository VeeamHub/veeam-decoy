#!/usr/bin/env python3

import asyncio
import logging
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
import configparser
import netifaces
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from collections import deque
import os
import psutil
from prettytable import PrettyTable
import traceback
import socket
import gzip
import shutil
from scapy.all import sniff, IP, TCP
import threading
import subprocess
import struct
import hashlib
import paramiko
import base64


SSH_PORT = 22
MAX_CONNECTIONS = 100
RATE_LIMIT = 10  
DEFAULT_SSH_BANNER = "SSH-2.0-OpenSSH_9.7" 


running = True
new_connections = deque(maxlen=1000)
connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)
rate_limiter = asyncio.Semaphore(RATE_LIMIT)


log_dir = '/var/log/hnp'
os.makedirs(log_dir, exist_ok=True)

class CompressedTimedRotatingFileHandler(TimedRotatingFileHandler):
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

log_file = os.path.join(log_dir, 'ssh_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {socket.gethostname()} ssh_honeypot - - - {record.getMessage()}"

file_handler.setFormatter(RFC5424Formatter())
logging.basicConfig(level=logging.DEBUG, handlers=[file_handler])
syslog_handler = SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(RFC5424Formatter())
logging.getLogger().addHandler(syslog_handler)

def log_event(event_type, source_ip, source_port, dest_ip, dest_port, additional_info=None):
    timestamp = datetime.datetime.now().isoformat()
    message = f"{timestamp} {event_type} source={source_ip}:{source_port} destination={dest_ip}:{dest_port}"
    if additional_info:
        message += f" {additional_info}"
    return message

def set_promiscuous_mode(interface):
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'], check=True)
        logging.info(f"Set {interface} to promiscuous mode")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set {interface} to promiscuous mode: {e}")

class SYNScanner(threading.Thread):
    def __init__(self, honeypot_ips, interfaces):
        threading.Thread.__init__(self)
        self.honeypot_ips = honeypot_ips
        self.interfaces = interfaces
        self.stop_event = threading.Event()

    def run(self):
        filter_expression = f"tcp[tcpflags] & (tcp-syn) != 0 and dst port {SSH_PORT}"

        for interface in self.interfaces:
            set_promiscuous_mode(interface)

        try:
            sniff(filter=filter_expression, prn=self.detect_syn_scan, store=0, stop_filter=self.should_stop, iface=self.interfaces)
        except Exception as e:
            logging.error(f"Error in SYN scanner: {str(e)}")

    def should_stop(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        self.stop_event.set()

    def detect_syn_scan(self, packet):
        if IP in packet and TCP in packet:
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            if dst_ip in self.honeypot_ips and dst_port == SSH_PORT:
                src_ip = packet[IP].src
                event = log_event("SYN_SCAN", src_ip, packet[TCP].sport, dst_ip, dst_port)
                logging.warning(event)
                new_connections.append(event)

def generate_ssh_key(random_rsa):
    key_file = '/etc/hnp/ssh_host_key'
    if random_rsa.lower() == 'yes' or not os.path.exists(key_file):
        key = paramiko.RSAKey.generate(2048)
        if random_rsa.lower() == 'no':
            key.write_private_key_file(key_file)
        logging.info("Generated new RSA key")
    else:
        key = paramiko.RSAKey(filename=key_file)
        logging.info("Loaded existing RSA key")
    return key

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, host, port, banner, random_rsa):
        self.host = host
        self.port = port
        self.banner = banner
        self.new_connections = new_connections
        self.event = threading.Event()
        self.random_rsa = random_rsa
        self.host_key = generate_ssh_key(self.random_rsa)

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logging.info(f"Auth attempt - Username: {username}, Password: {password}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    async def start_server(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(100)
            logging.info(f'SSH honeypot started on {self.host}:{self.port}')

            while True:
                client, addr = await asyncio.to_thread(sock.accept)
                asyncio.create_task(self.handle_client(client, addr))
        except Exception as e:
            logging.error(f"Error starting SSH server: {str(e)}")

    async def handle_client(self, client, addr):
        async with connection_semaphore:
            async with rate_limiter:
                transport = None
                try:
                    event = log_event("SSH_CONNECTION", addr[0], addr[1], self.host, self.port)
                    logging.info(event)
                    self.new_connections.append(event)

                    transport = paramiko.Transport(client)
                    transport.local_version = self.banner
                    if self.random_rsa.lower() == 'yes':
                        self.host_key = generate_ssh_key(self.random_rsa)
                    transport.add_server_key(self.host_key)

                    
                    transport.banner_timeout = 5

                    try:
                        await asyncio.wait_for(asyncio.to_thread(transport.start_server, server=self), timeout=10)
                    except asyncio.TimeoutError:
                        logging.warning(f"Timeout during SSH handshake with {addr[0]}:{addr[1]}")
                        return
                    except (paramiko.SSHException, EOFError) as e:
                        logging.warning(f"SSH Exception during handshake with {addr[0]}:{addr[1]}: {str(e)}")
                        return

                    
                    if hasattr(transport, 'remote_version'):
                        logging.info(f"Received client version: {transport.remote_version}")

                    try:
                        channel = await asyncio.wait_for(asyncio.to_thread(transport.accept), timeout=10)
                    except asyncio.TimeoutError:
                        logging.warning(f"Timeout waiting for channel from {addr[0]}:{addr[1]}")
                        return

                    if channel is None:
                        logging.warning(f"No channel opened for {addr[0]}:{addr[1]}")
                        return

                    try:
                        await asyncio.wait_for(asyncio.to_thread(self.event.wait), timeout=10)
                    except asyncio.TimeoutError:
                        logging.warning(f"No shell request received from {addr[0]}:{addr[1]}")
                        return

                    channel.send("Welcome to the SSH Honeypot!\r\n")
                    channel.send("Username: ")
                    username = (await asyncio.wait_for(asyncio.to_thread(channel.recv, 1024), timeout=10)).strip().decode('utf-8')
                    channel.send("Password: ")
                    password = (await asyncio.wait_for(asyncio.to_thread(channel.recv, 1024), timeout=10)).strip().decode('utf-8')

                    logging.info(f"Login attempt - Username: {username}, Password: {password}")

                    channel.send("\r\nAuthentication failed.\r\n")
                    await asyncio.sleep(1)
                    channel.close()

                except Exception as e:
                    logging.error(f"Error handling SSH client {addr[0]}:{addr[1]}: {str(e)}")
                    logging.error(traceback.format_exc())
                finally:
                    if transport:
                        transport.close()
                    logging.info(f"Connection closed for {addr[0]}:{addr[1]}")

def get_interface_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

async def start_honeypot(interfaces, banner, random_rsa):
    tasks = []
    honeypot_ips = set()
    for interface in interfaces:
        ip = get_interface_ip(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue
        honeypot_ips.add(ip)
        honeypot = SSHHoneypot(ip, SSH_PORT, banner, random_rsa)
        task = asyncio.create_task(honeypot.start_server())
        tasks.append(task)

    syn_scanner = SYNScanner(honeypot_ips, interfaces)
    syn_scanner.start()

    return tasks, syn_scanner

def send_email(config):
    if not config.get('Enabled', 'No').lower() == 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    from_name = config.get('from_name', 'SSH Honeypot')
    msg['From'] = formataddr((from_name, config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = f"SSH Honeypot Connection Summary - {socket.gethostname()}"

    table = PrettyTable()
    table.field_names = ["Timestamp", "Event Type", "Source", "Destination", "Additional Info"]
    table.align = "l"
    table.max_width = 30

    for connection in new_connections:
        try:
            parts = connection.split(maxsplit=4)
            timestamp = parts[0]
            event_type = parts[1]
            source = parts[2].split('=')[1]
            destination = parts[3].split('=')[1]
            additional_info = parts[4] if len(parts) > 4 else ""

            table.add_row([timestamp, event_type, source, destination, additional_info])
        except Exception as e:
            logging.error(f"Error processing connection: {str(e)}. Connection data: {connection[:50]}")
            table.add_row(["Error", "Processing Error", str(e), "", connection[:50]])

    body = f"New connections and events in the last 5 minutes:\n\n{table}\n\nTotal events: {len(new_connections)}"
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        server = smtplib.SMTP(config['smtp_server'], int(config['smtp_port']))
        server.starttls()
        server.login(config['smtp_username'], config['smtp_password'])
        server.send_message(msg)
        server.quit()
        logging.info("Email sent successfully")
        return True
    except Exception as e:
        logging.error(f"An error occurred while sending the email: {str(e)}. Please check your email configuration.")
        return False

async def email_summary(config):
    global new_connections
    while running:
        await asyncio.sleep(300)  
        if new_connections:
            logging.info(f"Events received in the last 5 minutes: {len(new_connections)}")
            if config.get('Enabled', 'No').lower() == 'yes':
                if send_email(config):
                    new_connections.clear()  
                else:
                    logging.error("Failed to send email summary. Please check your SMTP configuration in /etc/hnp/config.")
            else:
                logging.info("Email sending is disabled. Skipping email summary.")
                new_connections.clear()  
        else:
            logging.info("No new events to report")

async def monitor_resources():
    while running:
        cpu_percent = psutil.cpu_percent(interval=1)
        mem_percent = psutil.virtual_memory().percent
        if cpu_percent > 80 or mem_percent > 80:
            logging.warning(f"High resource usage: CPU {cpu_percent}%, RAM {mem_percent}%")
        await asyncio.sleep(60)  

def verify_config(config):
    required_sections = ['Email', 'SSH']
    required_email_keys = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password', 'from_email', 'to_email', 'Enabled']
    required_ssh_keys = ['interfaces', 'banner', 'random_rsa']

    missing = []

    for section in required_sections:
        if section not in config:
            missing.append(f"Section [{section}]")
        elif section == 'Email':
            for key in required_email_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [Email]")
        elif section == 'SSH':
            for key in required_ssh_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [SSH]")

    return missing

def load_config():
    config = configparser.ConfigParser()
    config.read('/etc/hnp/config')

    missing = verify_config(config)
    if missing:
        error_msg = "The configuration file /etc/hnp/config is not properly configured. The following elements are missing:\n"
        error_msg += "\n".join(missing)
        raise ConfigError(error_msg)

    return config

class ConfigError(Exception):
    pass

async def main():
    global running
    try:
        config = load_config()
    except ConfigError as e:
        logging.error(str(e))
        logging.error("The SSH honeypot cannot start due to configuration errors.")
        return

    ssh_config = config['SSH']
    interfaces = ssh_config.get('interfaces').split(',')
    banner = ssh_config.get('banner', DEFAULT_SSH_BANNER)
    random_rsa = ssh_config.get('random_rsa', 'No')

    logging.info(f"Starting SSH honeypot on interfaces: {', '.join(interfaces)}")
    logging.info(f"Using SSH banner: {banner}")
    logging.info(f"Random RSA key generation: {random_rsa}")

    tasks, syn_scanner = await start_honeypot(interfaces, banner, random_rsa)

    email_task = asyncio.create_task(email_summary(config['Email']))
    monitor_task = asyncio.create_task(monitor_resources())

    try:
        await asyncio.gather(*tasks, email_task, monitor_task)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.error(f"Unexpected error in main task: {str(e)}")
        logging.error(traceback.format_exc())
    finally:
        running = False
        for task in tasks:
            task.cancel()
        email_task.cancel()
        monitor_task.cancel()
        syn_scanner.stop()
        syn_scanner.join()

    logging.info("SSH honeypot stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopping the SSH honeypot due to keyboard interrupt...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())
