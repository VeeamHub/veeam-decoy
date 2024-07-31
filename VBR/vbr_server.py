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
from scapy.all import sniff, IP, TCP, conf
import threading
import socket
import gzip
import shutil
import struct
import subprocess


hostname = socket.gethostname()


PORTS = {
    "veeam": [9392, 9401, 2500, 2600, 9395, 6172, 9419, 5696, 9420],
    "postgresql": [5432],
    "sqlserver": [1433]
}

running = True

new_connections = deque(maxlen=1000)

MAX_CONNECTIONS = 100
connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)

RATE_LIMIT = 10  
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

log_file = os.path.join(log_dir, 'vbr_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30  
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {hostname} vbr_honeypot - - - {record.getMessage()}"

file_handler.setFormatter(RFC5424Formatter())

logging.basicConfig(level=logging.INFO, handlers=[file_handler])

syslog_handler = SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(RFC5424Formatter())
logging.getLogger().addHandler(syslog_handler)


def log_event(event_type, source_ip, source_port, dest_ip, dest_port):
    timestamp = datetime.datetime.now().isoformat()
    message = f"{timestamp} {event_type} source={source_ip}:{source_port} destination={dest_ip}:{dest_port}"
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
        all_ports = PORTS["veeam"] + PORTS["postgresql"] + PORTS["sqlserver"]
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
            
            if dst_ip in self.honeypot_ips and dst_port in PORTS["veeam"] + PORTS["postgresql"] + PORTS["sqlserver"]:
                
                if dst_port != 9420:
                    src_ip = packet[IP].src
                    event = log_event("SYN_SCAN", src_ip, packet[TCP].sport, dst_ip, dst_port)
                    logging.warning(event)
                    new_connections.append(event)
                else:
                    
                    logging.debug(f"SYN packet detected on port 9420 from {packet[IP].src}:{packet[TCP].sport}")

class HoneypotServer:
    def __init__(self, host, port, db_type):
        self.host = host
        self.port = port
        self.db_type = db_type
        self.new_connections = new_connections

    async def handle_client(self, reader, writer):
        async with connection_semaphore:
            addr = writer.get_extra_info('peername')
            event = log_event("CONNECTION", addr[0], addr[1], self.host, self.port)
            logging.info(event)
            self.new_connections.append(event)

            try:
                if self.port == 9420:
                    await self.handle_9420_connection(reader, writer)
                else:
                    data = await asyncio.wait_for(reader.read(1024), timeout=10.0)
                    event = log_event("DATA_RECEIVED", addr[0], addr[1], self.host, self.port)
                    logging.info(f"{event} data={data.hex()}")

                    if self.port == 9392:
                        response = self.handle_veeam_console_connection(addr, data)
                    elif self.port in PORTS["veeam"]:
                        response = self.handle_veeam_request(data)
                    elif self.db_type == "postgresql":
                        response = self.handle_postgresql_request(data, addr)
                    elif self.db_type == "sqlserver":
                        response = self.handle_sqlserver_request(data, addr)
                    else:
                        response = b"Invalid request\n"

                    writer.write(response)
                    await writer.drain()
            except asyncio.CancelledError:
                logging.info(f"Connection cancelled for {addr[0]}:{addr[1]}")
            except ConnectionResetError:
                logging.info(f"Connection reset by peer from {addr[0]}:{addr[1]}")
            except asyncio.TimeoutError:
                event = log_event("TIMEOUT", addr[0], addr[1], self.host, self.port)
                logging.info(event)
            except Exception as e:
                event = log_event("ERROR", addr[0], addr[1], self.host, self.port)
                logging.error(f"{event} error={str(e)}")
            finally:
                if not writer.is_closing():
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception as e:
                        logging.error(f"Error closing connection for {addr[0]}:{addr[1]}: {str(e)}")

    async def handle_9420_connection(self, reader, writer):
        try:
            addr = writer.get_extra_info('peername')
            event = log_event("VEEAM_CONSOLE_ATTEMPT", addr[0], addr[1], self.host, self.port)
            logging.info(event)
            self.new_connections.append(event)

            
            size_data = await reader.readexactly(4)
            message_size = struct.unpack('>I', size_data)[0]

            
            data = await reader.readexactly(message_size - 4)
            full_message = size_data + data
            decoded_data = full_message.decode('utf-8', errors='ignore')
            logging.info(f"Received data on port 9420: {decoded_data}")

            if b"net.tcp://" in full_message:
                event = log_event("VEEAM_CONSOLE_CONNECTED", addr[0], addr[1], self.host, self.port)
                logging.info(event)
                self.new_connections.append(event)

                
                preamble = struct.pack('>IHHHHQ', 0, 1, 0, 0, 1, 0)
                response_content = b"<Envelope><Header><Action>FramingMode</Action></Header><Body><FramingMode>Singleton</FramingMode></Body></Envelope>"
                sized_envelope = struct.pack('>I', len(response_content)) + response_content
                via = struct.pack('>I', len(self.host)) + self.host.encode('utf-8')
                framing_response = preamble + sized_envelope + via

                writer.write(framing_response)
                await writer.drain()

                
                await asyncio.sleep(2)

                
                writer.close()
                await writer.wait_closed()

                event = log_event("VEEAM_CONSOLE_DISCONNECTED", addr[0], addr[1], self.host, self.port)
                logging.info(event)
                self.new_connections.append(event)
            else:
                writer.write(b"Error: Expected net.tcp:// connection")
                await writer.drain()
        except asyncio.IncompleteReadError:
            logging.info(f"Incomplete read from {addr[0]}:{addr[1]} on port 9420")
        except ConnectionResetError:
            logging.info(f"Connection reset by peer from {addr[0]}:{addr[1]} on port 9420")
        except Exception as e:
            logging.error(f"Error handling connection on port 9420 from {addr[0]}:{addr[1]}: {str(e)}")
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()

    def handle_veeam_console_connection(self, addr, data):
        event = log_event("VEEAM_CONSOLE_CONNECTION", addr[0], addr[1], self.host, self.port)
        logging.warning(event)
        
        logging.info(f"{event} data={data.hex()}")
        
        try:
            decoded_data = data.decode('utf-8')
            logging.info(f"{event} decoded_data={decoded_data}")
        except UnicodeDecodeError:
            logging.info(f"{event} data_decode_failed=True")
        
        readable_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:50])
        logging.info(f"{event} readable_data={readable_data}")
        
        if b"Veeam.Backup.DBManager" in data:
            logging.info(f"{event} pattern_detected=Veeam.Backup.DBManager")
        if b"Veeam.Backup.Core" in data:
            logging.info(f"{event} pattern_detected=Veeam.Backup.Core")
        
        response = b'\x00\x00\x00\x00'
        logging.info(f"{event} response={response.hex()}")
        
        return response

    def handle_veeam_request(self, data):
        if self.port == 6172:
            return b"Veeam Backup & Replication REST API\n"
        elif self.port == 9419:
            return b"Veeam Backup & Replication REST API Client\n"
        elif self.port == 5696:
            return b"Veeam Backup & Replication Key Management System (KMS)\n"
        else:
            return b"Veeam Backup & Replication Service\n"

    def handle_postgresql_request(self, data, addr):
        if b"SELECT user_name,password,description,change_time_utc FROM credentials" in data:
            event = log_event("CREDENTIALS_EXTRACTION_ATTEMPT", addr[0], addr[1], self.host, self.port)
            logging.warning(f"{event} database_type=PostgreSQL")
            return b"ERROR:  permission denied for table credentials\n"
        elif b"SELECT" in data.upper():
            return b"ERROR:  syntax error at or near \"SELECT\"\nLINE 1: SELECT\n        ^\n"
        else:
            return b"ERROR:  invalid command\n"

    def handle_sqlserver_request(self, data, addr):
        if b"SELECT user_name,password,description,change_time_utc FROM [dbo].[Credentials]" in data:
            event = log_event("CREDENTIALS_EXTRACTION_ATTEMPT", addr[0], addr[1], self.host, self.port)
            logging.warning(f"{event} database_type=SQLServer")
            return b"Msg 229, Level 14, State 5, Server VeeamSQL, Line 1\nThe SELECT permission was denied on the object 'Credentials', database 'VeeamBackup', schema 'dbo'.\n"
        elif b"SELECT" in data.upper():
            return b"Msg 102, Level 15, State 1, Server VeeamSQL, Line 1\nIncorrect syntax near 'SELECT'.\n"
        else:
            return b"Msg 105, Level 15, State 1, Server VeeamSQL, Line 1\nUnclosed quotation mark after the character string.\n"

def get_interface_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (ValueError, KeyError, IndexError):
        return None

def get_all_interfaces():
    return [iface for iface in netifaces.interfaces() if get_interface_ip(iface)]

async def start_server(host, port, db_type):
    honeypot = HoneypotServer(host, port, db_type)
    
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

async def start_honeypot(interfaces, db_type):
    tasks = []
    honeypot_ips = set()
    for interface in interfaces:
        ip = get_interface_ip(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue
        honeypot_ips.add(ip)
        for port in PORTS["veeam"] + PORTS[db_type]:
            task = asyncio.create_task(start_server(ip, port, db_type))
            tasks.append(task)
    
    
    syn_scanner = SYNScanner(honeypot_ips, interfaces)
    syn_scanner.start()
    
    return tasks, syn_scanner

def send_email(config):
    if not config.get('Enabled', 'No').lower() == 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    from_name = config.get('from_name', 'Veeam Backup Server Honeypot')
    msg['From'] = formataddr((from_name, config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = f"Veeam Backup Server Honeypot Connection Summary - {hostname}"

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
            logging.error(f"Error processing connection: {connection}. Error: {str(e)}")
            table.add_row(["Error", "Processing Error", str(e), connection[:50]])
    
    body = f"New connections and scans in the last 5 minutes:\n\n{table.get_string()}\n\nTotal events: {len(new_connections)}"
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
        error_msg = f"An error occurred while sending the email: {str(e)}. Please check your email configuration."
        logging.error(error_msg)
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
    required_sections = ['Email', 'VBR']
    required_email_keys = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password', 'from_email', 'to_email', 'Enabled']
    required_vbr_keys = ['interfaces', 'database_type']
    
    missing = []

    for section in required_sections:
        if section not in config:
            missing.append(f"Section [{section}]")
        elif section == 'Email':
            for key in required_email_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [Email]")
        elif section == 'VBR':
            for key in required_vbr_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [VBR]")

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
        logging.error("The VBR honeypot cannot start due to configuration errors.")
        return

    vbr_config = config['VBR']
    interfaces = vbr_config.get('interfaces').split(',')
    database_type = vbr_config.get('database_type')

    logging.info(f"Starting Veeam Backup Server honeypot on interfaces: {', '.join(interfaces)}")
    logging.info(f"Emulating database: {database_type}")

    tasks, syn_scanner = await start_honeypot(interfaces, database_type)
    
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

    logging.info("VBR honeypot stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopping the VBR honeypot...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())
