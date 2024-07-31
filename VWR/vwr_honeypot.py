#!/usr/bin/env python3

import asyncio
import logging
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
import configparser
import netifaces
import random
import os
import socket
import gzip
import shutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import smtplib
from collections import deque
from prettytable import PrettyTable
import datetime
import psutil
import threading
from scapy.all import sniff, IP, TCP
import subprocess


FIXED_PORTS = [135, 139, 445, 5985, 6160, 6162, 6190, 6290, 11731]
DYNAMIC_PORTS_RANGE = (49152, 65535)
NUM_DYNAMIC_PORTS = 10


running = True
new_connections = deque(maxlen=1000)
hostname = socket.gethostname()


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

log_file = os.path.join(log_dir, 'vwr_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {hostname} vwr_honeypot - - - {record.getMessage()}"

file_handler.setFormatter(RFC5424Formatter())
logging.basicConfig(level=logging.INFO, handlers=[file_handler])
syslog_handler = SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(RFC5424Formatter())
logging.getLogger().addHandler(syslog_handler)

def log_event(event_type, source_ip, source_port, dest_ip, dest_port):
    timestamp = datetime.datetime.now().isoformat()
    message = f"{timestamp} {event_type} source={source_ip}:{source_port} destination={dest_ip}:{dest_port}"
    return message

class VWRHoneypot:
    def __init__(self, host, port, server_name):
        self.host = host
        self.port = port
        self.server_name = server_name

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        event = log_event("CONNECTION", addr[0], addr[1], self.host, self.port)
        logging.info(event)
        new_connections.append(event)

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            event = log_event("DATA_RECEIVED", addr[0], addr[1], self.host, self.port)
            logging.info(f"{event} data={data.hex()}")

            response = self.generate_response(data)
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

    def generate_response(self, data):
        if self.port in [135, 139, 445]:
            return b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00"  
        elif self.port == 5985:
            return b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n\r\n"
        elif self.port in [6160, 6162, 6190, 6290]:
            return f"Veeam Backup Repository Service on {self.server_name}\n".encode()
        elif self.port == 11731:
            return f"Veeam Backup Transport Service on {self.server_name}\n".encode()
        else:
            return f"Veeam Windows Repository Service on {self.server_name}\n".encode()

def set_promiscuous_mode(interface):
    try:
        subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'], check=True)
        logging.info(f"Set {interface} to promiscuous mode")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set {interface} to promiscuous mode: {e}")

class SYNScanner(threading.Thread):
    def __init__(self, honeypot_ips, interfaces, ports):
        threading.Thread.__init__(self)
        self.honeypot_ips = honeypot_ips
        self.interfaces = interfaces
        self.ports = ports
        self.stop_event = threading.Event()

    def run(self):
        for interface in self.interfaces:
            set_promiscuous_mode(interface)
        
        try:
            sniff(prn=self.packet_callback, store=0, stop_filter=self.should_stop, iface=self.interfaces)
        except Exception as e:
            logging.error(f"Error in SYN scanner: {str(e)}")

    def should_stop(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        self.stop_event.set()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            if packet[TCP].flags == 'S':
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                
                if dst_ip in self.honeypot_ips and dst_port in self.ports:
                    src_ip = packet[IP].src
                    event = log_event("SYN_SCAN", src_ip, packet[TCP].sport, dst_ip, dst_port)
                    logging.warning(event)
                    new_connections.append(event)

def get_interface_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

def load_config():
    config = configparser.ConfigParser()
    config.read('/etc/hnp/config')
    
    if 'VWR' not in config:
        raise ConfigError("The [VWR] section is missing from the configuration file")
    
    vwr_config = config['VWR']
    server_name = vwr_config.get('server_name', 'VEEAM-WIN-REPO')
    interfaces = vwr_config.get('interfaces', '').split(',')
    
    if not interfaces:
        raise ConfigError("No interfaces specified in the configuration file")
    
    return server_name, interfaces, config['Email'] if 'Email' in config else None

class ConfigError(Exception):
    pass

async def start_server(host, port, server_name):
    honeypot = VWRHoneypot(host, port, server_name)
    server = await asyncio.start_server(honeypot.handle_client, host, port)
    logging.info(f'Server started on {host}:{port}')
    async with server:
        await server.serve_forever()

async def start_honeypot(server_name, interfaces):
    tasks = []
    honeypot_ips = set()
    all_ports = FIXED_PORTS + random.sample(range(*DYNAMIC_PORTS_RANGE), NUM_DYNAMIC_PORTS)
    
    for interface in interfaces:
        ip = get_interface_ip(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue
        
        honeypot_ips.add(ip)
        for port in all_ports:
            task = asyncio.create_task(start_server(ip, port, server_name))
            tasks.append(task)
    
    
    syn_scanner = SYNScanner(honeypot_ips, interfaces, all_ports)
    syn_scanner.start()
    
    return tasks, syn_scanner

def send_email(config):
    if not config or config.get('Enabled', 'No').lower() != 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    from_name = config.get('from_name', 'VWR Honeypot')
    msg['From'] = formataddr((from_name, config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = f"VWR Honeypot Connection Summary - {hostname}"

    table = PrettyTable()
    table.field_names = ["Timestamp", "Event Type", "Source", "Destination"]
    table.align = "l"
    table.max_width = 30
    
    for connection in new_connections:
        parts = connection.split()
        timestamp = parts[0]
        event_type = parts[1]
        source = parts[2].split('=')[1]
        destination = parts[3].split('=')[1]
        table.add_row([timestamp, event_type, source, destination])
    
    body = f"New connections and scans in the last 5 minutes:\n\n{table}\n\nTotal events: {len(new_connections)}"
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_username'], config['smtp_password'])
        server.send_message(msg)
        server.quit()
        logging.info("Email sent successfully")
        return True
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return False

async def email_summary(config):
    global new_connections
    while running:
        await asyncio.sleep(300)  
        if new_connections:
            if config and config.get('Enabled', 'No').lower() == 'yes':
                if send_email(config):
                    new_connections.clear()
                else:
                    logging.error("Failed to send email summary.")
            else:
                logging.info(f"{len(new_connections)} events were logged.")
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

async def main():
    global running
    try:
        server_name, interfaces, email_config = load_config()
    except ConfigError as e:
        logging.error(str(e))
        return

    logging.info(f"Starting VWR honeypot with server name: {server_name}")
    logging.info(f"Listening on interfaces: {', '.join(interfaces)}")

    tasks, syn_scanner = await start_honeypot(server_name, interfaces)
    email_task = asyncio.create_task(email_summary(email_config))
    monitor_task = asyncio.create_task(monitor_resources())

    try:
        await asyncio.gather(*tasks, email_task, monitor_task)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
    finally:
        running = False
        for task in tasks:
            task.cancel()
        email_task.cancel()
        monitor_task.cancel()
        syn_scanner.stop()
        syn_scanner.join()

    logging.info("VWR honeypot stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopping the VWR honeypot...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
