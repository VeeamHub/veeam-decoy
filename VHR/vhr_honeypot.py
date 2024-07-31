#!/usr/bin/env python3

import asyncio
import logging
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
import signal
import netifaces
import datetime
import configparser
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
import random
from scapy.all import sniff, IP, TCP, conf
import threading
import subprocess


VHR_PORTS = [6160, 6162] + random.sample(range(2500, 3301), 10)

running = True
new_connections = deque(maxlen=1000)
connection_semaphore = asyncio.Semaphore(100)
rate_limiter = asyncio.Semaphore(10)

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

log_file = os.path.join(log_dir, 'vhr_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {socket.gethostname()} vhr_honeypot - - - {record.getMessage()}"

file_handler.setFormatter(RFC5424Formatter())
logging.basicConfig(level=logging.INFO, handlers=[file_handler])
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
        port_filter = " or ".join([f"dst port {port}" for port in VHR_PORTS])
        filter_expression = f"tcp[tcpflags] & (tcp-syn) != 0 and ({port_filter})"
        
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
            
            if dst_ip in self.honeypot_ips and dst_port in VHR_PORTS:
                src_ip = packet[IP].src
                event = log_event("SYN_SCAN", src_ip, packet[TCP].sport, dst_ip, dst_port)
                logging.warning(event)
                new_connections.append(event)

class VHRHoneypot:
    def __init__(self, host, port, server_name):
        self.host = host
        self.port = port
        self.server_name = server_name
        self.new_connections = new_connections

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        event = log_event("CONNECTION", addr[0], addr[1], self.host, self.port)
        logging.info(event)
        self.new_connections.append(event)

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            event = log_event("DATA_RECEIVED", addr[0], addr[1], self.host, self.port)
            logging.info(f"{event} data={data.hex()}")

            response = self.generate_vhr_response(data)
            writer.write(response)
            await writer.drain()
        except asyncio.TimeoutError:
            event = log_event("TIMEOUT", addr[0], addr[1], self.host, self.port)
            logging.info(event)
        except Exception as e:
            event = log_event("ERROR", addr[0], addr[1], self.host, self.port)
            logging.error(f"{event} error={str(e)}")
        finally:
            writer.close()
            await writer.wait_closed()

    def generate_vhr_response(self, data):
        
        if b"CONNECT" in data:
            return b"VHR_OK\r\n"
        elif b"STATUS" in data:
            return f"VHR_STATUS: ACTIVE\r\nSERVER: {self.server_name}\r\n".encode()
        elif b"CAPACITY" in data:
            return b"VHR_CAPACITY: 10TB\r\n"
        else:
            return b"VHR_ERROR: Unknown command\r\n"

def get_interface_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

async def start_server(host, port, server_name):
    honeypot = VHRHoneypot(host, port, server_name)
    
    async def connection_handler(reader, writer):
        async with rate_limiter:
            await honeypot.handle_client(reader, writer)
    
    try:
        server = await asyncio.start_server(connection_handler, host, port)
        logging.info(f'Server started on {host}:{port}')
        async with server:
            await server.serve_forever()
    except Exception as e:
        logging.error(f"Could not start server on {host}:{port}: {str(e)}")

async def start_honeypot(interfaces, server_name):
    tasks = []
    honeypot_ips = set()
    for interface in interfaces:
        ip = get_interface_ip(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue
        honeypot_ips.add(ip)
        for port in VHR_PORTS:
            task = asyncio.create_task(start_server(ip, port, server_name))
            tasks.append(task)
    
    
    syn_scanner = SYNScanner(honeypot_ips, interfaces)
    syn_scanner.start()
    
    return tasks, syn_scanner

def send_email(config):
    if not config.get('Enabled', 'No').lower() == 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    from_name = config.get('from_name', 'VHR Honeypot')
    msg['From'] = formataddr((from_name, config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = f"VHR Honeypot Connection Summary - {socket.gethostname()}"

    table = PrettyTable()
    table.field_names = ["Timestamp", "Event Type", "Source", "Destination"]
    table.align = "l"
    table.max_width = 30
    
    for connection in new_connections:
        try:
            parts = connection.split()
            timestamp = parts[0]
            event_type = parts[1]
            source = parts[2].split('=')[1]
            destination = parts[3].split('=')[1]
            
            table.add_row([timestamp, event_type, source, destination])
        except Exception as e:
            logging.error(f"Error processing connection: {str(e)}. Connection data: {connection[:50]}")
            table.add_row(["Error", "Processing Error", str(e), connection[:50]])
    
    body = f"New connections and scans in the last 5 minutes:\n\n{table}\n\nTotal events: {len(new_connections)}"
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
            logging.info(f"Connections received in the last 5 minutes: {len(new_connections)}")
            if config.get('Enabled', 'No').lower() == 'yes':
                if send_email(config):
                    new_connections.clear() 
                else:
                    logging.error("Failed to send email summary. Please check your SMTP configuration in /etc/hnp/config.")
            else:
                logging.info("Email sending is disabled. Skipping email summary.")
                new_connections.clear()  
        else:
            logging.info("No new connections to report")

async def monitor_resources():
    while running:
        cpu_percent = psutil.cpu_percent(interval=1)
        mem_percent = psutil.virtual_memory().percent
        if cpu_percent > 80 or mem_percent > 80:
            logging.warning(f"High resource usage: CPU {cpu_percent}%, RAM {mem_percent}%")
        await asyncio.sleep(60)  

def verify_config(config):
    required_sections = ['Email', 'VHR']
    required_email_keys = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password', 'from_email', 'to_email', 'Enabled']
    required_vhr_keys = ['interfaces', 'server_name']
    
    missing = []

    for section in required_sections:
        if section not in config:
            missing.append(f"Section [{section}]")
        elif section == 'Email':
            for key in required_email_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [Email]")
        elif section == 'VHR':
            for key in required_vhr_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [VHR]")

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
        logging.error("The VHR honeypot cannot start due to configuration errors.")
        return

    vhr_config = config['VHR']
    interfaces = vhr_config.get('interfaces').split(',')
    server_name = vhr_config.get('server_name')

    logging.info(f"Starting VHR honeypot on interfaces: {', '.join(interfaces)}")
    logging.info(f"Server name: {server_name}")
    logging.info(f"Listening on ports: {', '.join(map(str, VHR_PORTS))}")

    tasks, syn_scanner = await start_honeypot(interfaces, server_name)
    
    email_task = asyncio.create_task(email_summary(config['Email']))
    monitor_task = asyncio.create_task(monitor_resources())

    try:
        await asyncio.gather(*tasks, email_task, monitor_task)
    except asyncio.CancelledError:
        pass
    finally:
        running = False
        for task in tasks:
            task.cancel()
        email_task.cancel()
        monitor_task.cancel()
        syn_scanner.stop()
        syn_scanner.join()

    logging.info("VHR honeypot stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopping the VHR honeypot...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())
