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
import ssl
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from aiohttp import web
import struct
import io
import tempfile
from scapy.all import sniff, IP, TCP, conf
import threading
import subprocess


VBEM_PORTS = {
    "tcp": [9394, 9397, 9393],
    "http": [9080, 9399],
    "https": [9443, 6443, 9398]
}


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

log_file = os.path.join(log_dir, 'vbem_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {socket.gethostname()} vbem_honeypot - - - {record.getMessage()}"

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
        all_ports = sum(VBEM_PORTS.values(), [])
        port_filter = " or ".join([f"dst port {port}" for port in all_ports])
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
            
            if dst_ip in self.honeypot_ips and dst_port in sum(VBEM_PORTS.values(), []):
                src_ip = packet[IP].src
                event = log_event("SYN_SCAN", src_ip, packet[TCP].sport, dst_ip, dst_port)
                logging.warning(event)
                new_connections.append(event)

class VBEMHoneypot:
    def __init__(self, host, port, server_name, server_header):
        self.host = host
        self.port = port
        self.server_name = server_name
        self.server_header = server_header
        self.new_connections = new_connections

    async def handle_tcp_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        event = log_event("TCP_CONNECTION", addr[0], addr[1], self.host, self.port)
        logging.info(event)
        self.new_connections.append(event)

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            event = log_event("TCP_DATA_RECEIVED", addr[0], addr[1], self.host, self.port)
            logging.info(f"{event} data={data.hex()}")

            response = b"Veeam Backup Enterprise Manager Service\n"
            writer.write(response)
            await writer.drain()
        except asyncio.TimeoutError:
            event = log_event("TCP_TIMEOUT", addr[0], addr[1], self.host, self.port)
            logging.info(event)
        except Exception as e:
            event = log_event("TCP_ERROR", addr[0], addr[1], self.host, self.port)
            logging.error(f"{event} error={str(e)}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_http_request(self, request):
        peername = request.transport.get_extra_info('peername')
        event = log_event("HTTP_REQUEST", peername[0], peername[1], self.host, request.url.port)
        logging.info(event)
        self.new_connections.append(event)

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('NTLM '):
                ntlm_data = base64.b64decode(auth_header[5:])
                event = log_event("NTLM_AUTH_ATTEMPT", peername[0], peername[1], self.host, request.url.port)
                logging.info(f"{event} ntlm_data={ntlm_data.hex()}")
                
                
                if len(ntlm_data) > 10:  
                    
                    response = web.Response(text=self.get_login_page_html(), content_type='text/html')
                    response.headers['Server'] = self.server_header
                    return response
                else:
                    
                    challenge = self.create_ntlm_challenge()
                    response = web.Response(status=401, headers={'WWW-Authenticate': f'NTLM {base64.b64encode(challenge).decode()}'})
                    response.headers['Server'] = self.server_header
                    return response
        
        
        response = web.Response(status=401, headers={'WWW-Authenticate': 'NTLM'})
        response.headers['Server'] = self.server_header
        return response

    def create_ntlm_challenge(self):
        
        challenge = b'NTLMSSP\x00'  
        challenge += struct.pack('<I', 2)  
        challenge += struct.pack('<H', 0)  
        challenge += struct.pack('<H', 0)  
        challenge += struct.pack('<I', 0)  
        challenge += b'\x01\x02\x81\x00'  
        challenge += os.urandom(8)  
        challenge += b'\x00' * 8  
        return challenge

    def get_login_page_html(self):
        return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Veeam Backup Enterprise Manager</title>
            <style>
                body {
                    background-color: #00543d;
                    margin: 0;
                    padding: 0;
                    height: 100vh;
                    width: 100vw;
                }
            </style>
        </head>
        <body>
        </body>
        </html>
        '''

def generate_self_signed_cert(server_name):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, server_name)
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(server_name)]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return cert_pem, key_pem

async def start_server(host, port, server_name, server_header):
    honeypot = VBEMHoneypot(host, port, server_name, server_header)
    server = None
    
    if port in VBEM_PORTS["tcp"]:
        server = await asyncio.start_server(honeypot.handle_tcp_client, host, port)
        logging.info(f'TCP server started on {host}:{port}')
    elif port in VBEM_PORTS["http"] or port in VBEM_PORTS["https"]:
        app = web.Application()
        app.router.add_route('*', '/{tail:.*}', honeypot.handle_http_request)
        
        if port in VBEM_PORTS["https"]:
            cert_pem, key_pem = generate_self_signed_cert(server_name)
            
            
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as cert_file, \
                 tempfile.NamedTemporaryFile(delete=False, mode='wb') as key_file:
                cert_file.write(cert_pem)
                key_file.write(key_pem)
                cert_file_name = cert_file.name
                key_file_name = key_file.name

            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                ssl_context.load_cert_chain(certfile=cert_file_name, keyfile=key_file_name)
                runner = web.AppRunner(app)
                await runner.setup()
                site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
            finally:
                
                os.unlink(cert_file_name)
                os.unlink(key_file_name)
        else:
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, host, port)
        
        await site.start()
        server = site
        logging.info(f'{"HTTPS" if port in VBEM_PORTS["https"] else "HTTP"} server started on {host}:{port}')
    else:
        logging.error(f"Unknown port type: {port}")
    
    return server

async def start_honeypot(interfaces, server_name, server_header):
    tasks = []
    honeypot_ips = set()
    for interface in interfaces:
        ip = get_interface_ip(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue
        honeypot_ips.add(ip)
        for port_list in VBEM_PORTS.values():
            for port in port_list:
                task = asyncio.create_task(start_server(ip, port, server_name, server_header))
                tasks.append(task)
    
    
    syn_scanner = SYNScanner(honeypot_ips, interfaces)
    syn_scanner.start()
    
    return tasks, syn_scanner

def send_email(config):
    if not config.get('Enabled', 'No').lower() == 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    from_name = config.get('from_name', 'VBEM Honeypot')
    msg['From'] = formataddr((from_name, config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = f"VBEM Honeypot Connection Summary - {socket.gethostname()}"

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

def get_interface_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

def verify_config(config):
    required_sections = ['Email', 'VBEM']
    required_email_keys = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password', 'from_email', 'to_email', 'Enabled']
    required_vbem_keys = ['interfaces', 'server_name', 'server_header']
    
    missing = []

    for section in required_sections:
        if section not in config:
            missing.append(f"Section [{section}]")
        elif section == 'Email':
            for key in required_email_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [Email]")
        elif section == 'VBEM':
            for key in required_vbem_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [VBEM]")

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
        logging.error("The VBEM honeypot cannot start due to configuration errors.")
        return

    vbem_config = config['VBEM']
    interfaces = vbem_config.get('interfaces').split(',')
    server_name = vbem_config.get('server_name')
    server_header = vbem_config.get('server_header')

    logging.info(f"Starting VBEM honeypot on interfaces: {', '.join(interfaces)}")
    logging.info(f"Server name: {server_name}")
    logging.info(f"Server header: {server_header}")

    tasks, syn_scanner = await start_honeypot(interfaces, server_name, server_header)
    
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

    logging.info("VBEM honeypot stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopping the VBEM honeypot...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())
