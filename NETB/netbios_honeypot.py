#!/usr/bin/env python3

import asyncio
import logging
from logging.handlers import TimedRotatingFileHandler, SysLogHandler
import socket
import configparser
import struct
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from collections import deque
import netifaces
from prettytable import PrettyTable
import datetime
import traceback
import os
import gzip
import shutil


hostname = socket.gethostname()

NETBIOS_PORT = 137

running = True

new_connections = deque(maxlen=1000)

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

log_file = os.path.join(log_dir, 'netbios_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30  
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {hostname} netbios_honeypot - - - {record.getMessage()}"

file_handler.setFormatter(RFC5424Formatter())


logging.basicConfig(level=logging.INFO, handlers=[file_handler])


syslog_handler = SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(RFC5424Formatter())
logging.getLogger().addHandler(syslog_handler)


def log_event(event_type, source_ip, source_port, dest_ip, dest_port):
    if source_ip != dest_ip:  
        timestamp = datetime.datetime.now().isoformat()
        message = f"{timestamp} {event_type} source={source_ip}:{source_port} destination={dest_ip}:{dest_port}"
        return message
    return None

class NetBIOSHoneypot(asyncio.DatagramProtocol):
    def __init__(self, host, port, server_name, workgroup):
        self.host = host
        self.port = port
        self.server_name = server_name
        self.workgroup = workgroup
        self.transport = None

    def create_netbios_response(self):
        response = bytearray([
            0xe5, 0xd8, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41
        ])
        response += b"A" * 27
        response += bytearray([0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x03])

        server_name_padded = self.server_name.ljust(16).encode()[:16]
        response += server_name_padded + b"\x20\x20\x00\x04\x00"

        workgroup_padded = self.workgroup.ljust(15).encode()[:15]
        response += workgroup_padded + b"\x20\x00\x84\x00"

        response += server_name_padded + b"\x20\x20\x20\x04\x00\x80"

        response += bytearray([
            0x18, 0x44, 0xef, 0x80, 0x98, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ])

        return response

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        event = log_event("NETBIOS_CONNECTION", addr[0], addr[1], self.host, self.port)
        if event:
            logging.info(event)
            new_connections.append(event)

        response = self.create_netbios_response()
        self.transport.sendto(response, addr)

        event = log_event("NETBIOS_RESPONSE_SENT", self.host, self.port, addr[0], addr[1])
        if event:
            logging.info(event)

def get_interface_ip(interface):
    try:
        addrs = netifaces.ifaddresses(interface)
        logging.debug(f"Addresses for {interface}: {addrs}")
        if netifaces.AF_INET in addrs:
            return addrs[netifaces.AF_INET][0]['addr']
    except Exception as e:
        logging.error(f"Error getting IP for {interface}: {str(e)}")
    return None

def load_config():
    config = configparser.ConfigParser()
    config.read('/etc/hnp/config')

    if 'NETBIOS' not in config:
        raise ConfigError("The [NETBIOS] section is not present in the configuration file")

    if 'Email' not in config:
        raise ConfigError("The [Email] section is not present in the configuration file")

    netbios_config = config['NETBIOS']
    server_name = netbios_config.get('server_name', 'VEEAM-SERVER')
    workgroup = netbios_config.get('workgroup', 'WORKGROUP')
    interfaces = netbios_config.get('interfaces', '').split(',')

    if not interfaces:
        raise ConfigError("No interfaces specified in the configuration file")

    email_config = config['Email']
    
    
    email_config['Enabled'] = email_config.get('Enabled', 'No')

    return server_name, workgroup, interfaces, email_config

class ConfigError(Exception):
    pass

def send_email(config, subject, body):
    if config.get('Enabled', 'No').lower() != 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    msg['From'] = formataddr((config.get('from_name', 'NETBIOS Honeypot'), config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = subject

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
            subject = f"NETBIOS Honeypot Connection Summary - {hostname}"

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

            body = f"New NETBIOS connections in the last 5 minutes:\n\n{table}\n\nTotal connections: {len(new_connections)}"
            
            if config.get('Enabled', 'No').lower() == 'yes':
                if send_email(config, subject, body):
                    logging.info(f"Email sent with {len(new_connections)} connections")
                    new_connections.clear()  
                else:
                    logging.error("Failed to send email summary. Please check your SMTP configuration in /etc/hnp/config.")
            else:
                logging.info(f"Email sending is disabled. {len(new_connections)} connections were logged.")
                new_connections.clear()  
        else:
            logging.info("No new connections to report")

async def main():
    global running
    try:
        server_name, workgroup, interfaces, email_config = load_config()
    except ConfigError as e:
        logging.error(str(e))
        logging.error("The NETBIOS honeypot cannot start due to configuration errors.")
        return

    logging.info(f"Starting NETBIOS honeypot with server name: {server_name}, workgroup: {workgroup}")
    logging.info(f"Listening on interfaces: {', '.join(interfaces)}")

    loop = asyncio.get_running_loop()
    tasks = []

    for interface in interfaces:
        ip = get_interface_ip(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: NetBIOSHoneypot(ip, NETBIOS_PORT, server_name, workgroup),
                local_addr=(ip, NETBIOS_PORT)
            )
            tasks.append(protocol)
            logging.info(f"NETBIOS honeypot started on {ip}:{NETBIOS_PORT}")
        except Exception as e:
            logging.error(f"Could not start NETBIOS honeypot on {ip}:{NETBIOS_PORT}: {str(e)}")
            logging.error(traceback.format_exc())

    if not tasks:
        logging.error("Could not start NETBIOS honeypot on any interface")
        return

    email_task = asyncio.create_task(email_summary(email_config))

    try:
        await asyncio.gather(email_task, *[asyncio.sleep(3600) for _ in tasks])
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())
    finally:
        running = False
        email_task.cancel()
        for protocol in tasks:
            if protocol.transport:
                protocol.transport.close()

    logging.info("NETBIOS honeypot stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Stopping the NETBIOS honeypot...")
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        logging.error(traceback.format_exc())
