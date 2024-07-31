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
import struct
from prettytable import PrettyTable
import gzip
import shutil
import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from scapy.all import sniff, IP, TCP, conf
import threading
import subprocess
import random
import uuid
import hashlib
import traceback
import tempfile
import ipaddress


RDP_PORT = 3389
MAX_CONNECTIONS = 100
RATE_LIMIT = 10  


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

log_file = os.path.join(log_dir, 'rdp_honeypot.log')
file_handler = CompressedTimedRotatingFileHandler(
    log_file,
    when="midnight",
    interval=1,
    backupCount=30
)

class RFC5424Formatter(logging.Formatter):
    def format(self, record):
        timestamp = self.formatTime(record, datefmt='%Y-%m-%dT%H:%M:%S')
        return f"<{record.levelno}>1 {timestamp} {socket.gethostname()} rdp_honeypot - - - {record.getMessage()}"

file_handler.setFormatter(RFC5424Formatter())
logging.basicConfig(level=logging.DEBUG, handlers=[file_handler])
syslog_handler = SysLogHandler(address='/dev/log')
syslog_handler.setFormatter(RFC5424Formatter())
logging.getLogger().addHandler(syslog_handler)

def get_local_ip():
    try:
        ip_addresses = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
        return ip_addresses[0] if ip_addresses else "N/A"
    except Exception:
        return "N/A"

def get_ip_addresses():
    ip_addresses = {}
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_addresses[interface] = addrs[netifaces.AF_INET][0]['addr']
    return ip_addresses

def log_event(event_type, source_ip, source_port, dest_ip, dest_port, additional_info=None):
    timestamp = datetime.datetime.now().isoformat()
    source = f"{source_ip}:{source_port}" if source_ip != "N/A" else "N/A"
    destination = f"{dest_ip}:{dest_port}" if dest_ip != "N/A" else "N/A"
    message = f"{timestamp} {event_type} source={source} destination={destination}"
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
        logging.info("Starting SYN scanner")
        filter_expression = f"tcp[tcpflags] & (tcp-syn) != 0 and dst port {RDP_PORT}"
        
        for interface in self.interfaces:
            set_promiscuous_mode(interface)
        
        try:
            sniff(filter=filter_expression, prn=self.detect_syn_scan, store=0, stop_filter=self.should_stop, iface=self.interfaces)
        except Exception as e:
            logging.error(f"Error in SYN scanner: {str(e)}")
            logging.error(traceback.format_exc())

    def should_stop(self, packet):
        return self.stop_event.is_set()

    def stop(self):
        logging.info("Stopping SYN scanner")
        self.stop_event.set()

    def detect_syn_scan(self, packet):
        if IP in packet and TCP in packet:
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            if dst_ip in self.honeypot_ips and dst_port == RDP_PORT:
                src_ip = packet[IP].src
                event = log_event("SYN_SCAN", src_ip, packet[TCP].sport, dst_ip, dst_port)
                logging.warning(event)
                new_connections.append(event)

class RDPHoneypot:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_random = os.urandom(32)
        self.rdp_version = random.choice(["5.1", "5.2", "6.0", "6.1", "7.0", "7.1", "8.0", "8.1", "10.0"])
        self.capabilities = self.generate_capabilities()
        self.error_probability = 0.05  
        self.certificate = self.load_or_generate_cert()

    def load_or_generate_cert(self):
        cert_path = '/etc/hnp/rdp_cert.pem'
        key_path = '/etc/hnp/rdp_key.pem'
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            logging.info("Loading existing certificate and key")
            with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
                return {
                    'cert_pem': cert_file.read(),
                    'key_pem': key_file.read()
                }
        else:
            logging.info("Generating new self-signed certificate")
            return self.generate_self_signed_cert()

    def generate_self_signed_cert(self):
        logging.info("Generating self-signed certificate")
        try:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"RDP Server"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Veeam"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"IT"),
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
                x509.SubjectAlternativeName([x509.DNSName(u"localhost"), x509.IPAddress(ipaddress.ip_address(self.host))]),
                critical=False,
            ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            ).sign(key, hashes.SHA256(), default_backend())

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            
            with open('/etc/hnp/rdp_cert.pem', 'wb') as cert_file, open('/etc/hnp/rdp_key.pem', 'wb') as key_file:
                cert_file.write(cert_pem)
                key_file.write(key_pem)

            logging.info("Certificate generation completed")
            return {
                'cert_pem': cert_pem,
                'key_pem': key_pem
            }
        except Exception as e:
            logging.error(f"Error in generate_self_signed_cert: {str(e)}")
            logging.error(traceback.format_exc())
            raise

    def generate_capabilities(self):
        return {
            "general": {
                "os_major": 6,
                "os_minor": 1,
                "protocol_version": 0x00080004,
                "compression_types": 0,
                "extra_flags": 1,
                "update_capability": 1,
                "remote_unshare": 0,
                "compression_level": 0,
                "refresh_rect": 0,
                "suppress_output": 0
            },
            "bitmap": {
                "support": 1,
                "preferred_bits_per_pixel": 32,
                "receive1bit": 1,
                "receive4bits": 1,
                "receive8bits": 1,
                "compression": 1
            },
            "order": {
                "support": 1,
                "ex_flags": 3,
                "text_flags": 1537
            },
            "bmp_codec": {
                "codec_id": 1,
                "codec_properties": b"\x01\x00\x00\x00"
            },
            "input": {
                "input_flags": 1,
                "keyboard_layout": 0,
                "keyboard_type": 4,
                "keyboard_subtype": 0,
                "keyboard_function_key": 12,
                "ime_filename": ""
            },
            "virtual_channel": {
                "flags": 0x80800000,
                "chunk_size": 1600
            }
        }

    async def rdp_protocol_simulation(self, reader, writer, client_ip, client_port):
        logging.info(f"Starting detailed RDP protocol simulation for {client_ip}:{client_port}")
        try:
            logging.debug("Starting connection initiation")
            await self.connection_initiation(reader, writer, client_ip, client_port)
            logging.debug("Starting basic settings exchange")
            await self.basic_settings_exchange(reader, writer, client_ip, client_port)
            logging.debug("Starting channel connection")
            await self.channel_connection(reader, writer, client_ip, client_port)
            logging.debug("Starting security commencement")
            await self.security_commencement(reader, writer, client_ip, client_port)
            logging.debug("Starting secure settings exchange")
            await self.secure_settings_exchange(reader, writer, client_ip, client_port)
            logging.debug("Starting licensing")
            await self.licensing(reader, writer, client_ip, client_port)
            logging.debug("Starting capabilities exchange")
            await self.capabilities_exchange(reader, writer, client_ip, client_port)
            logging.debug("Starting connection finalization")
            await self.connection_finalization(reader, writer, client_ip, client_port)
            
            logging.debug("Starting post-connection handling")
            await self.handle_post_connection(reader, writer, client_ip, client_port)
        except ssl.SSLError as e:
            logging.error(f"SSL Error during simulation: {str(e)}")
        except Exception as e:
            logging.error(log_event("PROTOCOL_ERROR", client_ip, client_port, self.host, self.port, f"error={str(e)}"))
            logging.error(traceback.format_exc())
        finally:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
        logging.info(f"Finished RDP simulation for {client_ip}:{client_port}")

    async def connection_initiation(self, reader, writer, client_ip, client_port):
        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            return
        logging.info(log_event("X224_CONNECTION_REQUEST", client_ip, client_port, self.host, self.port))

        response = self.create_x224_connection_confirm()
        await self.safe_write(writer, response, client_ip, client_port)
        logging.info(log_event("X224_CONNECTION_CONFIRM", client_ip, client_port, self.host, self.port))

    async def basic_settings_exchange(self, reader, writer, client_ip, client_port):
        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            return
        logging.info(log_event("MCS_CONNECT_INITIAL", client_ip, client_port, self.host, self.port))

        response = self.create_mcs_connect_response()
        await self.safe_write(writer, response, client_ip, client_port)
        logging.info(log_event("MCS_CONNECT_RESPONSE", client_ip, client_port, self.host, self.port))

    async def channel_connection(self, reader, writer, client_ip, client_port):
        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            return
        logging.info(log_event("MCS_ERECT_DOMAIN", client_ip, client_port, self.host, self.port))

        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            return
        logging.info(log_event("MCS_ATTACH_USER", client_ip, client_port, self.host, self.port))

        response = self.create_mcs_attach_user_confirm()
        await self.safe_write(writer, response, client_ip, client_port)
        logging.info(log_event("MCS_ATTACH_USER_CONFIRM", client_ip, client_port, self.host, self.port))

        for _ in range(3):  
            data = await self.safe_read(reader, 1024, client_ip, client_port)
            if data is None:
                return
            logging.info(log_event("MCS_CHANNEL_JOIN", client_ip, client_port, self.host, self.port))

            response = self.create_mcs_channel_join_confirm()
            await self.safe_write(writer, response, client_ip, client_port)
            logging.info(log_event("MCS_CHANNEL_JOIN_CONFIRM", client_ip, client_port, self.host, self.port))

    async def security_commencement(self, reader, writer, client_ip, client_port):
        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            return
        logging.info(log_event("SECURITY_EXCHANGE", client_ip, client_port, self.host, self.port))

    async def secure_settings_exchange(self, reader, writer, client_ip, client_port):
        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            return
        logging.info(log_event("CLIENT_INFO", client_ip, client_port, self.host, self.port))

        response = self.create_license_error()
        await self.safe_write(writer, response, client_ip, client_port)
        logging.info(log_event("LICENSE_ERROR", client_ip, client_port, self.host, self.port))

    async def licensing(self, reader, writer, client_ip, client_port):
        license_request = self.create_license_request()
        await self.safe_write(writer, license_request, client_ip, client_port)
        logging.info(log_event("LICENSE_REQUEST", client_ip, client_port, self.host, self.port))

        license_info = await self.safe_read(reader, 1024, client_ip, client_port)
        if license_info is None:
            logging.warning(log_event("LICENSE_INFO_MISSING", client_ip, client_port, self.host, self.port))
            return
        logging.info(log_event("LICENSE_INFO", client_ip, client_port, self.host, self.port))

        license_valid = self.create_license_valid()
        await self.safe_write(writer, license_valid, client_ip, client_port)
        logging.info(log_event("LICENSE_VALID", client_ip, client_port, self.host, self.port))

    async def capabilities_exchange(self, reader, writer, client_ip, client_port):
        demand_active = self.create_demand_active()
        await self.safe_write(writer, demand_active, client_ip, client_port)
        logging.info(log_event("DEMAND_ACTIVE", client_ip, client_port, self.host, self.port))

        confirm_active = await self.safe_read(reader, 1024, client_ip, client_port)
        if confirm_active is None:
            logging.warning(log_event("CONFIRM_ACTIVE_MISSING", client_ip, client_port, self.host, self.port))
            return

        logging.info(log_event("CONFIRM_ACTIVE", client_ip, client_port, self.host, self.port))

        client_capabilities = self.parse_confirm_active(confirm_active)
        logging.info(log_event("CLIENT_CAPABILITIES", client_ip, client_port, self.host, self.port, f"capabilities={client_capabilities}"))

    async def connection_finalization(self, reader, writer, client_ip, client_port):
        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            logging.warning(log_event("CLIENT_SYNCHRONIZE_MISSING", client_ip, client_port, self.host, self.port))
            return
        logging.info(log_event("CLIENT_SYNCHRONIZE", client_ip, client_port, self.host, self.port))

        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            logging.warning(log_event("CLIENT_CONTROL_COOPERATE_MISSING", client_ip, client_port, self.host, self.port))
            return
        logging.info(log_event("CLIENT_CONTROL_COOPERATE", client_ip, client_port, self.host, self.port))

        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            logging.warning(log_event("CLIENT_CONTROL_REQUEST_MISSING", client_ip, client_port, self.host, self.port))
            return
        logging.info(log_event("CLIENT_CONTROL_REQUEST", client_ip, client_port, self.host, self.port))

        data = await self.safe_read(reader, 1024, client_ip, client_port)
        if data is None:
            logging.warning(log_event("FONT_LIST_MISSING", client_ip, client_port, self.host, self.port))
            return
        logging.info(log_event("FONT_LIST", client_ip, client_port, self.host, self.port))

        sync = self.create_server_sync()
        await self.safe_write(writer, sync, client_ip, client_port)
        logging.info(log_event("SERVER_SYNCHRONIZE", client_ip, client_port, self.host, self.port))

        cooperate = self.create_server_control_cooperate()
        await self.safe_write(writer, cooperate, client_ip, client_port)
        logging.info(log_event("SERVER_CONTROL_COOPERATE", client_ip, client_port, self.host, self.port))

        granted = self.create_server_control_granted()
        await self.safe_write(writer, granted, client_ip, client_port)
        logging.info(log_event("SERVER_CONTROL_GRANTED", client_ip, client_port, self.host, self.port))

        font_map = self.create_font_map()
        await self.safe_write(writer, font_map, client_ip, client_port)
        logging.info(log_event("FONT_MAP", client_ip, client_port, self.host, self.port))

    async def handle_post_connection(self, reader, writer, client_ip, client_port):
        while True:
            data = await self.safe_read(reader, 1024, client_ip, client_port)
            if not data:
                break

            pdu_type = self.get_pdu_type(data)
            if pdu_type == 0x03:  
                logging.info(log_event("INPUT_EVENT", client_ip, client_port, self.host, self.port))
                
            elif pdu_type == 0x06:  
                logging.info(log_event("SUPPRESS_OUTPUT", client_ip, client_port, self.host, self.port))
            elif pdu_type == 0x08:  
                logging.info(log_event("REFRESH_RECT", client_ip, client_port, self.host, self.port))
                await self.send_fake_screen_update(writer, client_ip, client_port)
            else:
                logging.info(log_event("UNKNOWN_PDU", client_ip, client_port, self.host, self.port, f"pdu_type={pdu_type}"))

    def create_x224_connection_confirm(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00,
            0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x00, 0x00
        ])

    def create_mcs_connect_response(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x65, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x82, 0x01, 0xbe, 0x04, 0x01, 0x01, 0x04,
            0x01, 0x01, 0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02,
            0x30, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01,
            0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x02, 0x01, 0x02, 0x30, 0x1c, 0x02, 0x02, 0xff,
            0xff, 0x02, 0x02, 0xfc, 0x17, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02,
            0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 0x04, 0x82, 0x01, 0x4b, 0x00, 0x05, 0x00,
            0x14, 0x7c, 0x00, 0x01, 0x81, 0x42, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75,
            0x63, 0x61, 0x81, 0x34, 0x01, 0xc0, 0xd8, 0x00, 0x04, 0x00, 0x08, 0x00, 0x20, 0x03, 0x58, 0x02,
            0x01, 0xca, 0x03, 0xaa, 0x09, 0x04, 0x00, 0x00, 0x28, 0x0a, 0x00, 0x00
        ])

    def create_mcs_attach_user_confirm(self):
        return bytearray([
            0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
        ])

    def create_mcs_channel_join_confirm(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x38,
            0x00, 0x00, 0x03, 0xeb
        ])

    def create_demand_active(self):
        capabilities = struct.pack('>IIIIIIII', 
            self.capabilities['general']['protocol_version'],
            self.capabilities['general']['compression_types'],
            self.capabilities['general']['extra_flags'],
            self.capabilities['general']['update_capability'],
            self.capabilities['bitmap']['preferred_bits_per_pixel'],
            self.capabilities['input']['input_flags'],
            self.capabilities['virtual_channel']['flags'],
            len(self.capabilities)  
        )
        return b'\x03\x00' + struct.pack('>H', len(capabilities) + 4) + b'\x02\xf0\x80\x64' + capabilities

    def parse_confirm_active(self, data):
        if data is None or len(data) < 53:
            return {"general": "Invalid or incomplete data"}
        try:
            capabilities = {}
            capabilities['general'] = struct.unpack('>IIIIIIII', data[21:53])
            return capabilities
        except struct.error:
            return {"general": "Error unpacking data"}

    def get_pdu_type(self, data):
        if len(data) < 6:
            return None
        return data[5]

    async def send_fake_screen_update(self, writer, client_ip, client_port):
        update_pdu = bytearray([
            0x03, 0x00, 0x00, 0x1a,  
            0x02, 0xf0, 0x80,        
            0x68,                    
            0x00, 0x01, 0x00, 0x00,  
            0x00, 0x00, 0x00, 0x00,  
            0x00, 0x00, 0x00, 0x00,  
            0x00, 0x00, 0x00, 0x00   
        ])
        await self.safe_write(writer, update_pdu, client_ip, client_port)
        logging.info(log_event("FAKE_SCREEN_UPDATE_SENT", client_ip, client_port, self.host, self.port))

    def create_license_error(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x11, 0x02, 0xf0, 0x80, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x00
        ])

    def create_license_request(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80, 0x01,
            0x00, 0x00, 0x00
        ])

    def create_license_valid(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80, 0x02,
            0x00, 0x00, 0x00
        ])

    def create_server_sync(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x1c,
            0x00, 0x00, 0x00, 0x01
        ])

    def create_server_control_cooperate(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x14,
            0x00, 0x00, 0x00, 0x01
        ])

    def create_server_control_granted(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x14,
            0x00, 0x00, 0x00, 0x04
        ])

    def create_font_map(self):
        return bytearray([
            0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x38,
            0x00, 0x00, 0x00, 0x00
        ])

    async def safe_read(self, reader, n, client_ip, client_port):
        try:
            data = await asyncio.wait_for(reader.read(n), timeout=5.0)
            if not data:
                logging.info(f"Connection closed by client {client_ip}:{client_port}")
                return None
            return data
        except asyncio.TimeoutError:
            logging.info(log_event("READ_TIMEOUT", client_ip, client_port, self.host, self.port))
        except ConnectionResetError:
            logging.info(log_event("CONNECTION_RESET", client_ip, client_port, self.host, self.port))
        except Exception as e:
            logging.error(log_event("READ_ERROR", client_ip, client_port, self.host, self.port, f"error={str(e)}"))
            logging.error(traceback.format_exc())
        return None

    async def safe_write(self, writer, data, client_ip, client_port):
        try:
            writer.write(data)
            await writer.drain()
        except ConnectionResetError:
            logging.info(log_event("CONNECTION_RESET", client_ip, client_port, self.host, self.port))
        except BrokenPipeError:
            logging.info(log_event("BROKEN_PIPE", client_ip, client_port, self.host, self.port))
        except Exception as e:
            logging.error(log_event("WRITE_ERROR", client_ip, client_port, self.host, self.port, f"error={str(e)}"))
            logging.error(traceback.format_exc())

async def start_server(host, port, use_ssl=True):
    logging.info(f"Starting server on {host}:{port} with SSL: {use_ssl}")
    honeypot = RDPHoneypot(host, port)
    
    if use_ssl:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ssl_context.options &= ~ssl.OP_NO_TLSv1
        ssl_context.options &= ~ssl.OP_NO_TLSv1_1
        ssl_context.set_ciphers('DEFAULT')        
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as cert_file, \
                 tempfile.NamedTemporaryFile(delete=False, mode='wb') as key_file:
                cert_file.write(honeypot.certificate['cert_pem'])
                key_file.write(honeypot.certificate['key_pem'])
                cert_file_name = cert_file.name
                key_file_name = key_file.name

            ssl_context.load_cert_chain(certfile=cert_file_name, keyfile=key_file_name)
            logging.info("SSL context created successfully")
            logging.info(f"Certificate loaded: {bool(honeypot.certificate)}")
            logging.info(f"Certificate length: {len(honeypot.certificate['cert_pem'])}")
            logging.info(f"Key length: {len(honeypot.certificate['key_pem'])}")
        except Exception as e:
            logging.error(f"Error creating SSL context: {str(e)}")
            logging.error(traceback.format_exc())
            return
        finally:
            try:
                os.unlink(cert_file_name)
                os.unlink(key_file_name)
            except Exception as e:
                logging.error(f"Error removing temporary certificate files: {str(e)}")
    else:
        ssl_context = None
    
    try:
        server = await asyncio.start_server(
            lambda r, w: honeypot.rdp_protocol_simulation(r, w, w.get_extra_info('peername')[0], w.get_extra_info('peername')[1]),
            host, port, ssl=ssl_context
        )
        logging.info(f"SERVER_STARTED {host}:{port}")
        async with server:
            await server.serve_forever()
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {str(e)}")
    except OSError as e:
        logging.error(f"OS Error: {str(e)}")
    except Exception as e:
        logging.error(f"SERVER_START_ERROR {host}:{port} error={str(e)}")
        logging.error(traceback.format_exc())

async def start_honeypot(interfaces, use_ssl=True):
    tasks = []
    ip_addresses = get_ip_addresses()
    
    filtered_ip_addresses = {k: v for k, v in ip_addresses.items() if not v.startswith("127.")}
    
    logging.info(f"Starting RDP honeypot on interfaces: {', '.join(interfaces)} with SSL: {use_ssl}")

    honeypot_ips = set()
    for interface in interfaces:
        ip = filtered_ip_addresses.get(interface)
        if ip is None:
            logging.error(f"Could not get IP address for interface {interface}")
            continue
        
        logging.info(f"Starting RDP honeypot on interface {interface} with IP {ip}")
        
        honeypot_ips.add(ip)
        task = asyncio.create_task(start_server(ip, RDP_PORT, use_ssl))
        tasks.append(task)
    
    syn_scanner = SYNScanner(honeypot_ips, interfaces)
    syn_scanner.start()
    
    return tasks, syn_scanner

def send_email(config):
    if not config.get('Enabled', 'No').lower() == 'yes':
        logging.info("Email sending is disabled in the configuration.")
        return False

    msg = MIMEMultipart()
    from_name = config.get('from_name', 'RDP Honeypot')
    msg['From'] = formataddr((from_name, config['from_email']))
    msg['To'] = config['to_email']
    msg['Subject'] = f"RDP Honeypot Connection Summary - {socket.gethostname()}"

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
            logging.error(traceback.format_exc())
            table.add_row(["Error", "Processing Error", str(e), connection[:50], ""])
    
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
        logging.error(traceback.format_exc())
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
            logging.warning(log_event("HIGH_RESOURCE_USAGE", "N/A", "N/A", "N/A", "N/A", f"cpu={cpu_percent}% ram={mem_percent}%"))
        await asyncio.sleep(60)  

def verify_config(config):
    required_sections = ['Email', 'RDP']
    required_email_keys = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password', 'from_email', 'to_email', 'Enabled']
    required_rdp_keys = ['interfaces', 'use_ssl']
    
    missing = []

    for section in required_sections:
        if section not in config:
            missing.append(f"Section [{section}]")
        elif section == 'Email':
            for key in required_email_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [Email]")
        elif section == 'RDP':
            for key in required_rdp_keys:
                if key not in config[section]:
                    missing.append(f"Key '{key}' in section [RDP]")

    return missing

def load_config():
    logging.info("Loading configuration")
    config = configparser.ConfigParser()
    config_file = '/etc/hnp/config'
    try:
        config.read(config_file)
        missing = verify_config(config)
        if missing:
            error_msg = "The configuration file /etc/hnp/config is not properly configured. The following elements are missing:\n"
            error_msg += "\n".join(missing)
            raise ConfigError(error_msg)
        logging.info("Configuration loaded successfully")
        return config
    except Exception as e:
        logging.error(f"Error loading configuration: {str(e)}")
        logging.error(traceback.format_exc())
        raise

class ConfigError(Exception):
    pass

async def main():
    global running
    local_ip = get_local_ip()
    logging.info(f"Starting RDP honeypot on {local_ip}")
    try:
        config = load_config()
    except ConfigError as e:
        logging.error(log_event("CONFIG_ERROR", local_ip, "N/A", "N/A", "N/A", f"error={str(e)}"))
        logging.error("The RDP honeypot cannot start due to configuration errors.")
        return

    rdp_config = config['RDP']
    interfaces = rdp_config.get('interfaces').split(',')
    use_ssl = rdp_config.getboolean('use_ssl', True)
    logging.info(f"Configured interfaces: {interfaces}")
    logging.info(f"Using SSL: {use_ssl}")

    tasks = []
    syn_scanner = None
    email_task = None
    monitor_task = None

    try:
        logging.info("Starting honeypot...")
        tasks, syn_scanner = await start_honeypot(interfaces, use_ssl)
        
        logging.info("Setting up email task...")
        email_task = asyncio.create_task(email_summary(config['Email']))
        
        logging.info("Setting up monitor task...")
        monitor_task = asyncio.create_task(monitor_resources())

        logging.info("Gathering all tasks...")
        await asyncio.gather(*tasks, email_task, monitor_task)
    except asyncio.CancelledError:
        logging.info(log_event("TASKS_CANCELLED", local_ip, "N/A", "N/A", "N/A"))
    except Exception as e:
        logging.error(log_event("MAIN_TASK_ERROR", local_ip, "N/A", "N/A", "N/A", f"error={str(e)}"))
        logging.error(f"Traceback: {traceback.format_exc()}")
    finally:
        running = False
        if tasks:
            for task in tasks:
                task.cancel()
        if email_task:
            email_task.cancel()
        if monitor_task:
            monitor_task.cancel()
        if syn_scanner:
            syn_scanner.stop()
            syn_scanner.join()
        logging.info("All tasks cancelled and cleaned up")

    logging.info(log_event("HONEYPOT_STOPPED", local_ip, "N/A", "N/A", "N/A"))

if __name__ == "__main__":
    local_ip = get_local_ip()
    try:
        logging.info("Starting main function")
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info(log_event("KEYBOARD_INTERRUPT", local_ip, "N/A", "N/A", "N/A"))
    except Exception as e:
        logging.error(log_event("UNEXPECTED_ERROR", local_ip, "N/A", "N/A", "N/A", f"error={str(e)}"))
        logging.error(f"Traceback: {traceback.format_exc()}")
