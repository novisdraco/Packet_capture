#!/usr/bin/env python3
"""
DIAGNOSTIC High-Performance IDS with Enhanced Troubleshooting
This version includes extensive diagnostics to identify packet capture issues
"""

# Core imports
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit
import socket
import struct
import threading
import sys
import psutil
import ipaddress
from datetime import datetime, timedelta
import json
import time
import queue
from collections import deque, defaultdict
import logging
import subprocess
import platform
import os

# Configure detailed logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ids_debug.log')
    ]
)
logger = logging.getLogger(__name__)

# =============================================================================
# DIAGNOSTIC FUNCTIONS
# =============================================================================

def check_system_requirements():
    """Check system requirements and permissions"""
    issues = []
    solutions = []
    
    # Check if running as admin/root
    try:
        if platform.system() == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                issues.append("❌ Not running as Administrator")
                solutions.append("💡 Right-click and 'Run as Administrator'")
        else:
            if os.geteuid() != 0:
                issues.append("❌ Not running as root")
                solutions.append("💡 Run with: sudo python3 script.py")
    except Exception as e:
        issues.append(f"❌ Permission check failed: {e}")
    
    # Check raw socket support
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_socket.close()
        logger.info("✅ Raw socket creation successful")
    except PermissionError:
        issues.append("❌ No permission for raw sockets")
        solutions.append("💡 Run as Administrator/root")
    except Exception as e:
        issues.append(f"❌ Raw socket test failed: {e}")
    
    # Check network interfaces
    try:
        interfaces = psutil.net_if_addrs()
        active_interfaces = []
        for name, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    active_interfaces.append((name, addr.address))
        
        if active_interfaces:
            logger.info(f"✅ Found {len(active_interfaces)} network interfaces")
            for name, ip in active_interfaces[:3]:  # Show first 3
                logger.info(f"   📡 {name}: {ip}")
        else:
            issues.append("❌ No suitable network interfaces found")
            solutions.append("💡 Check network connection")
    except Exception as e:
        issues.append(f"❌ Interface enumeration failed: {e}")
    
    return issues, solutions

def test_packet_capture_capability(interface_ip):
    """Test if we can actually capture packets on the interface"""
    test_results = []
    
    try:
        # Test 1: Can we create a raw socket?
        logger.info(f"🔍 Testing packet capture on {interface_ip}...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        test_results.append("✅ Raw socket created successfully")
        
        # Test 2: Can we bind to the interface?
        try:
            sock.bind((interface_ip, 0))
            test_results.append(f"✅ Successfully bound to {interface_ip}")
        except Exception as e:
            test_results.append(f"❌ Bind failed: {e}")
            sock.close()
            return test_results
        
        # Test 3: Can we set socket options?
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            test_results.append("✅ IP_HDRINCL option set")
        except Exception as e:
            test_results.append(f"❌ Socket option failed: {e}")
        
        # Test 4: Windows promiscuous mode
        if platform.system() == "Windows":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                test_results.append("✅ Windows promiscuous mode enabled")
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception as e:
                test_results.append(f"⚠️ Promiscuous mode failed: {e}")
        
        # Test 5: Can we receive data? (timeout test)
        try:
            sock.settimeout(2.0)  # 2 second timeout
            logger.info("🔍 Testing packet reception (2 second timeout)...")
            data, addr = sock.recvfrom(1024)
            test_results.append(f"✅ Received packet: {len(data)} bytes from {addr}")
        except socket.timeout:
            test_results.append("⚠️ No packets received in 2 seconds (might be normal)")
        except Exception as e:
            test_results.append(f"❌ Packet reception failed: {e}")
        
        sock.close()
        
    except Exception as e:
        test_results.append(f"❌ Capture test failed: {e}")
    
    return test_results

# =============================================================================
# SIMPLIFIED TOPOLOGY TRACKER
# =============================================================================

class SimpleNetworkHost:
    def __init__(self, ip_address: str):
        self.ip_address = ip_address
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.packet_count = 0
        self.host_type = self._classify_host(ip_address)
        self.is_internal = self._is_internal_ip(ip_address)
        self.activity_level = 'low'
        self.threat_level = 0
        self.alert_count = 0
        self.lock = threading.Lock()
    
    def _classify_host(self, ip_address: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_loopback:
                return 'localhost'
            elif ip_obj.is_private:
                if ip_address.endswith('.1'):
                    return 'router'
                else:
                    return 'internal'
            else:
                return 'external'
        except:
            return 'unknown'
    
    def _is_internal_ip(self, ip_address: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            return False
    
    def update_activity(self, packet_info: dict):
        with self.lock:
            self.last_seen = datetime.now()
            self.packet_count += 1
            
            if self.packet_count > 50:
                self.activity_level = 'high'
            elif self.packet_count > 10:
                self.activity_level = 'medium'
            else:
                self.activity_level = 'low'

class SimpleTopologyTracker:
    def __init__(self):
        self.hosts = {}
        self.connections = {}
        self.stats = {
            'total_packets_processed': 0,
            'start_time': datetime.now()
        }
        self.lock = threading.Lock()
        logger.info("🌐 Simple Topology Tracker initialized")
    
    def process_packet(self, packet_info: dict):
        try:
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            
            if not src_ip or not dst_ip:
                return
            
            # Skip localhost-to-localhost
            if src_ip == '127.0.0.1' and dst_ip == '127.0.0.1':
                return
            
            with self.lock:
                # Update hosts
                if src_ip not in self.hosts:
                    self.hosts[src_ip] = SimpleNetworkHost(src_ip)
                    logger.debug(f"New host discovered: {src_ip}")
                
                if dst_ip not in self.hosts:
                    self.hosts[dst_ip] = SimpleNetworkHost(dst_ip)
                    logger.debug(f"New host discovered: {dst_ip}")
                
                self.hosts[src_ip].update_activity(packet_info)
                self.hosts[dst_ip].update_activity(packet_info)
                
                # Track connection
                conn_id = f"{src_ip}-{dst_ip}"
                if conn_id not in self.connections:
                    self.connections[conn_id] = {
                        'source': src_ip,
                        'target': dst_ip,
                        'packet_count': 0,
                        'first_seen': datetime.now()
                    }
                
                self.connections[conn_id]['packet_count'] += 1
                self.stats['total_packets_processed'] += 1
                
                # Log every 25 packets
                if self.stats['total_packets_processed'] % 25 == 0:
                    logger.info(f"🌐 Topology: {len(self.hosts)} hosts, {len(self.connections)} connections")
        
        except Exception as e:
            logger.error(f"Error processing packet for topology: {e}")
    
    def get_topology_data(self) -> dict:
        try:
            with self.lock:
                nodes = []
                for ip, host in self.hosts.items():
                    nodes.append({
                        'id': ip,
                        'ip_address': ip,
                        'host_type': host.host_type,
                        'is_internal': host.is_internal,
                        'packet_count': host.packet_count,
                        'activity_level': host.activity_level,
                        'threat_level': host.threat_level,
                        'alert_count': host.alert_count,
                        'last_seen': host.last_seen.isoformat()
                    })
                
                links = []
                for conn_id, conn in self.connections.items():
                    links.append({
                        'source': conn['source'],
                        'target': conn['target'],
                        'packet_count': conn['packet_count'],
                        'bandwidth_category': 'high' if conn['packet_count'] > 50 else 'medium' if conn['packet_count'] > 10 else 'low',
                        'threat_score': 0
                    })
                
                return {
                    'nodes': nodes,
                    'links': links,
                    'stats': self.stats,
                    'timestamp': datetime.now().isoformat()
                }
        
        except Exception as e:
            logger.error(f"Error getting topology data: {e}")
            return {'nodes': [], 'links': [], 'stats': {}, 'timestamp': datetime.now().isoformat()}

# =============================================================================
# ENHANCED PACKET CAPTURE WITH DIAGNOSTICS
# =============================================================================

class DiagnosticPacketCapture:
    def __init__(self):
        self.conn = None
        self.is_running = False
        self.topology_tracker = SimpleTopologyTracker()
        self.packet_stats = {
            'total_packets': 0,
            'total_alerts': 0,
            'start_time': None,
            'packets_per_second': 0,
            'last_rate_check': time.time(),
            'capture_errors': 0,
            'last_error': None
        }
        
        self.ui_update_thread = None
        self.topology_update_thread = None
        
        # Test data generation
        self.generate_test_data = False
        self.test_data_thread = None
    
    def start_capture(self, interface_ip):
        """Start packet capture with detailed diagnostics"""
        try:
            logger.info(f"🚀 Starting diagnostic packet capture on {interface_ip}")
            
            # Run diagnostics first
            issues, solutions = check_system_requirements()
            if issues:
                logger.warning("⚠️ System requirement issues found:")
                for issue in issues:
                    logger.warning(f"   {issue}")
                for solution in solutions:
                    logger.info(f"   {solution}")
            
            # Test capture capability
            test_results = test_packet_capture_capability(interface_ip)
            for result in test_results:
                logger.info(f"   {result}")
            
            # Check if we have any critical failures
            critical_failures = [r for r in test_results if r.startswith('❌') and ('Raw socket' in r or 'Bind failed' in r)]
            if critical_failures:
                logger.error("💥 Critical packet capture failures detected!")
                logger.info("🔄 Falling back to test data generation...")
                self.generate_test_data = True
                return self._start_test_mode(interface_ip)
            
            # Try to start real packet capture
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.conn.bind((interface_ip, 0))
            self.conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if sys.platform == "win32":
                try:
                    self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                    logger.info("✅ Windows promiscuous mode enabled")
                except Exception as e:
                    logger.warning(f"⚠️ Promiscuous mode failed: {e}")
            
            self.is_running = True
            self.packet_stats['start_time'] = datetime.now()
            
            # Start threads
            self._start_threads()
            
            logger.info(f"✅ Real packet capture started successfully on {interface_ip}")
            return True, None
            
        except Exception as e:
            logger.error(f"❌ Real packet capture failed: {e}")
            logger.info("🔄 Falling back to test data generation...")
            self.generate_test_data = True
            return self._start_test_mode(interface_ip)
    
    def _start_test_mode(self, interface_ip):
        """Start test mode with simulated data"""
        try:
            self.is_running = True
            self.packet_stats['start_time'] = datetime.now()
            
            # Start test data generation
            self.test_data_thread = threading.Thread(target=self._generate_test_packets, daemon=True)
            self.test_data_thread.start()
            
            # Start UI threads
            self._start_threads()
            
            logger.info("✅ Test mode started - generating simulated network data")
            return True, "Test mode: Generating simulated data"
            
        except Exception as e:
            logger.error(f"❌ Test mode failed: {e}")
            return False, str(e)
    
    def _start_threads(self):
        """Start background threads"""
        self.ui_update_thread = threading.Thread(target=self._ui_updater, daemon=True)
        self.ui_update_thread.start()
        
        self.topology_update_thread = threading.Thread(target=self._topology_updater, daemon=True)
        self.topology_update_thread.start()
    
    def _generate_test_packets(self):
        """Generate test packet data for demonstration"""
        logger.info("📊 Starting test packet generation...")
        
        test_ips = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '8.8.8.8', '1.1.1.1', '192.168.1.1'
        ]
        
        packet_id = 1
        
        while self.is_running:
            try:
                # Generate a test packet
                import random
                
                src_ip = random.choice(test_ips)
                dst_ip = random.choice(test_ips)
                
                if src_ip == dst_ip:
                    continue
                
                packet_info = {
                    'id': packet_id,
                    'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 22, 53, 21, 25]),
                    'size': random.randint(64, 1500),
                    'flags': random.choice(['SYN', 'ACK', 'SYN,ACK', 'FIN', None])
                }
                
                # Process packet
                self.topology_tracker.process_packet(packet_info)
                captured_packets.append(packet_info)
                
                # Generate occasional alerts for testing
                if random.random() < 0.05:  # 5% chance
                    alert = {
                        'id': packet_id,
                        'timestamp': packet_info['timestamp'],
                        'rule_name': random.choice(['Port Scan Detected', 'DDoS Attack Detected', 'Brute Force Attack']),
                        'description': 'Test alert for demonstration',
                        'severity': random.choice(['Low', 'Medium', 'High']),
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': packet_info['protocol'],
                        'packet_id': packet_id
                    }
                    alerts.append(alert)
                    self.packet_stats['total_alerts'] += 1
                
                self.packet_stats['total_packets'] += 1
                packet_id += 1
                
                # Calculate rate
                current_time = time.time()
                if current_time - self.packet_stats['last_rate_check'] >= 1.0:
                    self.packet_stats['packets_per_second'] = random.randint(10, 100)
                    self.packet_stats['last_rate_check'] = current_time
                
                # Vary the sleep time for realistic simulation
                time.sleep(random.uniform(0.01, 0.1))
                
            except Exception as e:
                logger.error(f"Test packet generation error: {e}")
                time.sleep(1)
    
    def capture_packets(self):
        """Real packet capture loop"""
        logger.info("🔍 Starting real packet analysis...")
        
        packet_count = 0
        last_rate_time = time.time()
        
        while self.is_running:
            try:
                raw_data, addr = self.conn.recvfrom(65535)
                packet_count += 1
                self.packet_stats['total_packets'] += 1
                
                # Calculate rate
                current_time = time.time()
                if current_time - last_rate_time >= 1.0:
                    self.packet_stats['packets_per_second'] = packet_count
                    packet_count = 0
                    last_rate_time = current_time
                
                # Parse packet
                packet_info = self.parse_packet(raw_data, self.packet_stats['total_packets'])
                
                # Process packet
                self.topology_tracker.process_packet(packet_info)
                captured_packets.append(packet_info)
                
                # Log first few packets for debugging
                if self.packet_stats['total_packets'] <= 5:
                    logger.info(f"📦 Packet {self.packet_stats['total_packets']}: {packet_info['src_ip']} → {packet_info['dst_ip']} [{packet_info['protocol']}]")
                
            except Exception as e:
                self.packet_stats['capture_errors'] += 1
                self.packet_stats['last_error'] = str(e)
                
                if self.is_running:
                    logger.error(f"Capture error: {e}")
                    time.sleep(0.1)  # Brief pause on error
                break
    
    def parse_packet(self, data, packet_num):
        """Parse packet data"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        try:
            if len(data) < 20:
                return {
                    'id': packet_num,
                    'timestamp': timestamp,
                    'src_ip': 'unknown',
                    'dst_ip': 'unknown',
                    'protocol': 'Unknown',
                    'size': len(data)
                }
            
            # Parse IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            version_ihl = ip_header[0]
            ihl = version_ihl & 0xF
            header_length = ihl * 4
            
            packet_info = {
                'id': packet_num,
                'timestamp': timestamp,
                'src_ip': socket.inet_ntoa(ip_header[8]),
                'dst_ip': socket.inet_ntoa(ip_header[9]),
                'protocol': self.get_protocol_name(ip_header[6]),
                'protocol_num': ip_header[6],
                'size': len(data),
                'src_port': None,
                'dst_port': None,
                'flags': None
            }
            
            # Parse transport layer
            if ip_header[6] == 6 and len(data) >= header_length + 20:  # TCP
                tcp_header = struct.unpack('!HHLLBBHHH', data[header_length:header_length+20])
                packet_info['src_port'] = tcp_header[0]
                packet_info['dst_port'] = tcp_header[1]
                
                flags = tcp_header[5]
                flag_names = []
                if flags & 0x02: flag_names.append('SYN')
                if flags & 0x10: flag_names.append('ACK')
                if flags & 0x01: flag_names.append('FIN')
                if flags & 0x04: flag_names.append('RST')
                packet_info['flags'] = ','.join(flag_names) if flag_names else None
                
            elif ip_header[6] == 17 and len(data) >= header_length + 8:  # UDP
                udp_header = struct.unpack('!HHHH', data[header_length:header_length+8])
                packet_info['src_port'] = udp_header[0]
                packet_info['dst_port'] = udp_header[1]
            
            return packet_info
            
        except Exception as e:
            logger.warning(f"Packet parse error: {e}")
            return {
                'id': packet_num,
                'timestamp': timestamp,
                'src_ip': 'parse_error',
                'dst_ip': 'parse_error',
                'protocol': 'Unknown',
                'size': len(data),
                'error': str(e)
            }
    
    def get_protocol_name(self, protocol_num):
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP'}
        return protocols.get(protocol_num, f'Protocol-{protocol_num}')
    
    def _ui_updater(self):
        """Background thread for UI updates"""
        while self.is_running:
            try:
                time.sleep(0.5)  # Update every 500ms
                
                # Send packet batch
                packets_to_send = list(captured_packets)[-15:]  # Last 15 packets
                if packets_to_send:
                    socketio.emit('packet_batch', packets_to_send)
                
                # Send alert batch
                alerts_to_send = list(alerts)[-10:]  # Last 10 alerts
                if alerts_to_send:
                    socketio.emit('alert_batch', alerts_to_send)
                
                # Send stats
                stats = {
                    'packets': self.packet_stats['total_packets'],
                    'alerts': self.packet_stats['total_alerts'],
                    'packets_per_second': self.packet_stats['packets_per_second'],
                    'queue_size': 0,
                    'capture_errors': self.packet_stats['capture_errors'],
                    'test_mode': self.generate_test_data
                }
                socketio.emit('stats_update', stats)
                
            except Exception as e:
                if self.is_running:
                    logger.error(f"UI update error: {e}")
    
    def _topology_updater(self):
        """Background thread for topology updates"""
        while self.is_running:
            try:
                time.sleep(2.0)  # Update every 2 seconds
                
                topology_data = self.topology_tracker.get_topology_data()
                
                nodes = topology_data.get('nodes', [])
                links = topology_data.get('links', [])
                
                if nodes or links:
                    socketio.emit('topology_update', topology_data)
                    logger.debug(f"📡 Sent topology update: {len(nodes)} nodes, {len(links)} links")
                
            except Exception as e:
                if self.is_running:
                    logger.error(f"Topology update error: {e}")
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        try:
            for interface_name, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        interfaces.append({
                            'name': interface_name,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        
        return interfaces
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        
        if self.conn:
            if sys.platform == "win32":
                try:
                    self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
            self.conn.close()
            self.conn = None
        
        logger.info("⏹️ Packet capture stopped")

# =============================================================================
# FLASK APPLICATION
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'diagnostic_ids_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables
capture_thread = None
is_capturing = False
captured_packets = deque(maxlen=500)
alerts = deque(maxlen=100)

# Packet capture instance
packet_capture = DiagnosticPacketCapture()

# HTML Template (simplified for diagnostics)
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnostic IDS with Network Topology</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        .header {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        .diagnostic-badge {
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
            color: white;
            padding: 6px 15px;
            border-radius: 25px;
            font-size: 0.85rem;
            font-weight: 700;
            animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 15px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        .stat-number { font-size: 1.6rem; font-weight: 700; color: #667eea; }
        .stat-label { color: #718096; font-size: 0.75rem; font-weight: 500; }
        .performance-number { color: #48bb78 !important; }
        .alert-stat { color: #e53e3e !important; }
        .topology-stat { color: #4f46e5 !important; }
        
        .controls, .status {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        
        label { display: block; margin-bottom: 5px; font-weight: 600; color: #4a5568; }
        select, button {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 16px;
            margin-bottom: 10px;
        }
        
        button {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            color: white;
            border: none;
            cursor: pointer;
            font-weight: 600;
        }
        button:disabled { background: #cbd5e0; cursor: not-allowed; }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .status-dot {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: #f56565;
            animation: pulse 2s infinite;
        }
        .status-dot.active { background: #48bb78; }
        .status-dot.test { background: #f59e0b; }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr;
            gap: 20px;
        }
        
        .network-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            height: 600px;
            display: flex;
            flex-direction: column;
        }
        
        .network-header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            color: white;
            padding: 15px 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            border-radius: 15px 15px 0 0;
        }
        
        .network-visualization {
            flex: 1;
            position: relative;
            overflow: hidden;
        }
        
        .network-svg {
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        }
        
        .alerts-packets-section {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }
        
        .alerts-container, .packets-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            height: 500px;
            display: flex;
            flex-direction: column;
        }
        
        .alerts-header {
            background: linear-gradient(135deg, #e53e3e 0%, #fc8181 100%);
            color: white;
            padding: 15px 20px;
            font-weight: 600;
            border-radius: 15px 15px 0 0;
        }
        
        .packets-header {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
            color: white;
            padding: 15px 20px;
            font-weight: 600;
            border-radius: 15px 15px 0 0;
        }
        
        .alerts-list, .packets-list {
            flex: 1;
            overflow-y: auto;
            padding: 10px;
        }
        
        .alert, .packet {
            border-bottom: 1px solid #e2e8f0;
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 8px;
            transition: background-color 0.2s ease;
        }
        
        .alert {
            background: linear-gradient(90deg, rgba(229, 62, 62, 0.08) 0%, transparent 100%);
            border-left: 4px solid #e53e3e;
            animation: alert-flash 0.5s ease-out;
        }
        
        @keyframes alert-flash {
            0% { background: rgba(229, 62, 62, 0.2); }
            100% { background: linear-gradient(90deg, rgba(229, 62, 62, 0.08) 0%, transparent 100%); }
        }
        
        .packet {
            background: #f8fafc;
            animation: packet-slide 0.3s ease-out;
        }
        
        @keyframes packet-slide {
            0% { transform: translateX(-10px); opacity: 0; }
            100% { transform: translateX(0); opacity: 1; }
        }
        
        .alert-title { font-weight: 600; color: #e53e3e; margin-bottom: 5px; }
        .alert-details, .packet-details {
            font-size: 0.9em;
            color: #4a5568;
            font-family: 'Consolas', 'Monaco', monospace;
            line-height: 1.4;
        }
        
        .packet-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        
        .packet-id { font-weight: 600; color: #48bb78; margin-right: 10px; }
        .protocol-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .protocol-tcp { background: #bee3f8; color: #2b6cb0; }
        .protocol-udp { background: #c6f6d5; color: #276749; }
        .protocol-icmp { background: #fed7d7; color: #c53030; }
        .protocol-other { background: #e2e8f0; color: #4a5568; }
        
        .no-items { text-align: center; padding: 40px; color: #718096; }
        
        /* Topology styles */
        .node { cursor: pointer; transition: all 0.3s ease; }
        .node:hover { stroke-width: 3px; filter: drop-shadow(0 0 8px rgba(0, 0, 0, 0.3)); }
        .link { stroke: #999; stroke-opacity: 0.6; transition: all 0.3s ease; }
        .link:hover { stroke-opacity: 1; stroke-width: 3px; }
        .node-label {
            font-size: 10px;
            text-anchor: middle;
            fill: #374151;
            font-family: 'Segoe UI', sans-serif;
            font-weight: 500;
            pointer-events: none;
            user-select: none;
        }
        
        .tooltip {
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1000;
            opacity: 0;
            transition: opacity 0.2s;
            max-width: 250px;
            line-height: 1.4;
        }
        .tooltip.show { opacity: 1; }
        
        .diagnostic-info {
            background: rgba(255, 243, 205, 0.9);
            border: 2px solid #f59e0b;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        
        .diagnostic-title {
            color: #92400e;
            font-weight: 700;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        @media (max-width: 1200px) {
            .alerts-packets-section { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                🛡️ Diagnostic IDS System
                <span class="diagnostic-badge">+ Enhanced Troubleshooting</span>
            </h1>
            <p>Network intrusion detection with automatic diagnostics and fallback modes</p>
        </div>
        
        <div class="diagnostic-info" id="diagnostic-info" style="display: none;">
            <div class="diagnostic-title">
                🔧 System Diagnostics
            </div>
            <div id="diagnostic-details">
                Running system diagnostics...
            </div>
        </div>
        
        <div class="dashboard">
            <div class="stat-card">
                <span class="stat-number performance-number" id="packet-rate">0</span>
                <div class="stat-label">Packets/Second</div>
            </div>
            <div class="stat-card">
                <span class="stat-number" id="packet-count">0</span>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <span class="stat-number alert-stat" id="alert-count">0</span>
                <div class="stat-label">Security Alerts</div>
            </div>
            <div class="stat-card">
                <span class="stat-number topology-stat" id="host-count">0</span>
                <div class="stat-label">Network Hosts</div>
            </div>
            <div class="stat-card">
                <span class="stat-number topology-stat" id="connection-count">0</span>
                <div class="stat-label">Connections</div>
            </div>
            <div class="stat-card">
                <span class="stat-number" id="capture-errors">0</span>
                <div class="stat-label">Capture Errors</div>
            </div>
        </div>
        
        <div class="controls">
            <label for="interface-select">Select Network Interface:</label>
            <select id="interface-select">
                <option value="">Loading interfaces...</option>
            </select>
            <button id="start-btn">Start Enhanced Monitoring</button>
            <button id="stop-btn" disabled>Stop Monitoring</button>
        </div>
        
        <div class="status">
            <div class="status-indicator">
                <div class="status-dot" id="status-dot"></div>
                <span id="status-text">Ready for enhanced monitoring with diagnostics</span>
            </div>
        </div>
        
        <div class="main-content">
            <div class="network-container">
                <div class="network-header">
                    🌐 Real-Time Network Topology Map
                    <span id="topology-count" style="margin-left: auto;">0 hosts, 0 connections</span>
                </div>
                <div class="network-visualization">
                    <svg class="network-svg" id="network-svg"></svg>
                </div>
            </div>
            
            <div class="alerts-packets-section">
                <div class="alerts-container">
                    <div class="alerts-header">
                        🚨 Security Alerts
                    </div>
                    <div class="alerts-list" id="alerts-list">
                        <div class="no-items">No security alerts yet. System ready for monitoring.</div>
                    </div>
                </div>
                
                <div class="packets-container">
                    <div class="packets-header">
                        📊 Network Traffic
                    </div>
                    <div class="packets-list" id="packets-list">
                        <div class="no-items">No packets captured yet. Start monitoring to see network traffic.</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="tooltip" id="tooltip"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
    <script>
        console.log('🚀 Starting Diagnostic IDS...');
        
        const socket = io();
        
        // UI Elements
        const elements = {
            interfaceSelect: document.getElementById('interface-select'),
            startBtn: document.getElementById('start-btn'),
            stopBtn: document.getElementById('stop-btn'),
            statusDot: document.getElementById('status-dot'),
            statusText: document.getElementById('status-text'),
            packetRate: document.getElementById('packet-rate'),
            packetCount: document.getElementById('packet-count'),
            alertCount: document.getElementById('alert-count'),
            hostCount: document.getElementById('host-count'),
            connectionCount: document.getElementById('connection-count'),
            captureErrors: document.getElementById('capture-errors'),
            topologyCount: document.getElementById('topology-count'),
            packetsList: document.getElementById('packets-list'),
            alertsList: document.getElementById('alerts-list'),
            tooltip: document.getElementById('tooltip'),
            diagnosticInfo: document.getElementById('diagnostic-info'),
            diagnosticDetails: document.getElementById('diagnostic-details')
        };
        
        let isCapturing = false;
        let isTestMode = false;
        let networkViz = null;
        
        // Initialize
        window.addEventListener('load', () => {
            loadInterfaces();
            initializeNetworkVisualization();
        });
        
        // Button events
        elements.startBtn.addEventListener('click', startCapture);
        elements.stopBtn.addEventListener('click', stopCapture);
        
        // Socket events
        socket.on('connected', (data) => {
            console.log('✅ Connected:', data.message);
        });
        
        socket.on('packet_batch', (packets) => {
            handlePacketBatch(packets);
        });
        
        socket.on('alert_batch', (alerts) => {
            handleAlertBatch(alerts);
        });
        
        socket.on('stats_update', (data) => {
            updateStats(data);
        });
        
        socket.on('topology_update', (data) => {
            handleTopologyUpdate(data);
        });
        
        socket.on('diagnostic_info', (data) => {
            showDiagnosticInfo(data);
        });
        
        function handlePacketBatch(packets) {
            if (!packets || packets.length === 0) return;
            
            const noItems = elements.packetsList.querySelector('.no-items');
            if (noItems) {
                elements.packetsList.innerHTML = '';
            }
            
            packets.slice(0, 15).forEach(packet => {
                const packetEl = createPacketElement(packet);
                elements.packetsList.insertBefore(packetEl, elements.packetsList.firstChild);
            });
            
            while (elements.packetsList.children.length > 30) {
                elements.packetsList.removeChild(elements.packetsList.lastChild);
            }
        }
        
        function handleAlertBatch(alerts) {
            if (!alerts || alerts.length === 0) return;
            
            console.log('🚨 Received alerts:', alerts);
            
            const noItems = elements.alertsList.querySelector('.no-items');
            if (noItems) {
                elements.alertsList.innerHTML = '';
            }
            
            alerts.forEach(alert => {
                const alertEl = createAlertElement(alert);
                elements.alertsList.insertBefore(alertEl, elements.alertsList.firstChild);
                playAlertSound();
            });
            
            while (elements.alertsList.children.length > 20) {
                elements.alertsList.removeChild(elements.alertsList.lastChild);
            }
        }
        
        function handleTopologyUpdate(data) {
            if (!data || !networkViz) return;
            
            console.log('🌐 Topology update:', data);
            
            const nodes = data.nodes || [];
            const links = data.links || [];
            
            elements.hostCount.textContent = nodes.length;
            elements.connectionCount.textContent = links.length;
            elements.topologyCount.textContent = `${nodes.length} hosts, ${links.length} connections`;
            
            networkViz.updateData(data);
        }
        
        function updateStats(data) {
            elements.packetCount.textContent = data.packets || 0;
            elements.alertCount.textContent = data.alerts || 0;
            elements.packetRate.textContent = data.packets_per_second || 0;
            elements.captureErrors.textContent = data.capture_errors || 0;
            
            // Show test mode indicator
            if (data.test_mode) {
                isTestMode = true;
                elements.statusDot.classList.add('test');
                elements.statusText.textContent += ' (Test Mode - Simulated Data)';
            }
        }
        
        function showDiagnosticInfo(data) {
            elements.diagnosticInfo.style.display = 'block';
            elements.diagnosticDetails.innerHTML = data.message || 'Diagnostic information received';
        }
        
        function createPacketElement(packet) {
            const div = document.createElement('div');
            div.className = 'packet';
            
            const protocolClass = getProtocolClass(packet.protocol);
            
            div.innerHTML = `
                <div class="packet-header">
                    <span class="packet-id">#${packet.id}</span>
                    <span class="protocol-badge ${protocolClass}">${packet.protocol}</span>
                    <span style="font-size: 0.8em; color: #718096;">${packet.timestamp}</span>
                </div>
                <div class="packet-details">
                    ${packet.src_ip}:${packet.src_port || '?'} → ${packet.dst_ip}:${packet.dst_port || '?'}<br>
                    Size: ${packet.size}B${packet.flags ? ' [' + packet.flags + ']' : ''}
                    ${isTestMode ? ' <span style="color: #f59e0b;">[TEST]</span>' : ''}
                </div>
            `;
            return div;
        }
        
        function createAlertElement(alert) {
            const div = document.createElement('div');
            div.className = 'alert';
            div.innerHTML = `
                <div class="alert-title">${alert.rule_name}</div>
                <div class="alert-details">
                    [${alert.timestamp}] ${alert.severity}<br>
                    ${alert.description}<br>
                    ${alert.src_ip} → ${alert.dst_ip} [${alert.protocol}]
                    ${isTestMode ? '<br><span style="color: #f59e0b;">[TEST ALERT]</span>' : ''}
                </div>
            `;
            return div;
        }
        
        function getProtocolClass(protocol) {
            switch (protocol?.toLowerCase()) {
                case 'tcp': return 'protocol-tcp';
                case 'udp': return 'protocol-udp';
                case 'icmp': return 'protocol-icmp';
                default: return 'protocol-other';
            }
        }
        
        function playAlertSound() {
            try {
                const audioContext = new (window.AudioContext || window.webkitAudioContext)();
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.value = 800;
                oscillator.type = 'sine';
                
                gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
                gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.3);
            } catch (error) {
                console.log('Audio not available');
            }
        }
        
        async function loadInterfaces() {
            try {
                const response = await fetch('/interfaces');
                const interfaces = await response.json();
                
                elements.interfaceSelect.innerHTML = '<option value="">Select interface...</option>';
                interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.ip;
                    option.textContent = `${iface.name} (${iface.ip})`;
                    elements.interfaceSelect.appendChild(option);
                });
                
                console.log(`✅ Loaded ${interfaces.length} interfaces`);
            } catch (error) {
                console.error('❌ Failed to load interfaces:', error);
                elements.interfaceSelect.innerHTML = '<option value="">Failed to load interfaces</option>';
            }
        }
        
        async function startCapture() {
            const interfaceIp = elements.interfaceSelect.value;
            if (!interfaceIp) {
                alert('Please select a network interface');
                return;
            }
            
            try {
                elements.startBtn.disabled = true;
                elements.startBtn.textContent = 'Starting...';
                
                const response = await fetch('/start_capture', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interface_ip: interfaceIp })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    isCapturing = true;
                    elements.startBtn.disabled = true;
                    elements.stopBtn.disabled = false;
                    elements.interfaceSelect.disabled = true;
                    elements.statusDot.classList.add('active');
                    
                    if (data.message && data.message.includes('Test mode')) {
                        elements.statusText.textContent = 'Test mode active - Generating simulated data for demonstration';
                        elements.statusDot.classList.add('test');
                        showDiagnosticInfo({message: '🔧 Real packet capture failed - Running in test mode with simulated data'});
                    } else {
                        elements.statusText.textContent = 'Enhanced IDS monitoring active - Real packet capture enabled';
                    }
                    
                    elements.packetsList.innerHTML = '<div class="no-items">Starting capture...</div>';
                    elements.alertsList.innerHTML = '<div class="no-items">Monitoring for threats...</div>';
                    
                    console.log('✅ Capture started');
                } else {
                    alert('Failed to start capture: ' + data.message);
                    elements.startBtn.disabled = false;
                }
                
                elements.startBtn.textContent = 'Start Enhanced Monitoring';
            } catch (error) {
                console.error('❌ Error starting capture:', error);
                alert('Error starting capture: ' + error.message);
                elements.startBtn.disabled = false;
                elements.startBtn.textContent = 'Start Enhanced Monitoring';
            }
        }
        
        async function stopCapture() {
            try {
                const response = await fetch('/stop_capture', { method: 'POST' });
                
                isCapturing = false;
                isTestMode = false;
                elements.startBtn.disabled = false;
                elements.stopBtn.disabled = true;
                elements.interfaceSelect.disabled = false;
                elements.statusDot.classList.remove('active', 'test');
                elements.statusText.textContent = 'Enhanced IDS stopped';
                elements.diagnosticInfo.style.display = 'none';
                
                console.log('✅ Capture stopped');
            } catch (error) {
                console.error('❌ Error stopping capture:', error);
            }
        }
        
        function initializeNetworkVisualization() {
            networkViz = new NetworkVisualization();
        }
        
        class NetworkVisualization {
            constructor() {
                this.svg = d3.select('#network-svg');
                this.width = 800;
                this.height = 500;
                this.nodes = [];
                this.links = [];
                
                this.setup();
            }
            
            setup() {
                this.svg.attr('viewBox', `0 0 ${this.width} ${this.height}`);
                
                this.simulation = d3.forceSimulation()
                    .force('link', d3.forceLink().id(d => d.id).distance(100))
                    .force('charge', d3.forceManyBody().strength(-300))
                    .force('center', d3.forceCenter(this.width / 2, this.height / 2));
                
                this.linkGroup = this.svg.append('g').attr('class', 'links');
                this.nodeGroup = this.svg.append('g').attr('class', 'nodes');
            }
            
            updateData(data) {
                this.nodes = data.nodes || [];
                this.links = data.links || [];
                
                this.render();
            }
            
            render() {
                const link = this.linkGroup.selectAll('.link')
                    .data(this.links, d => `${d.source}-${d.target}`);
                
                link.exit().remove();
                
                link.enter()
                    .append('line')
                    .attr('class', 'link')
                    .merge(link)
                    .attr('stroke', d => this.getLinkColor(d))
                    .attr('stroke-width', d => this.getLinkWidth(d));
                
                const node = this.nodeGroup.selectAll('.node')
                    .data(this.nodes, d => d.id);
                
                node.exit().remove();
                
                const nodeEnter = node.enter()
                    .append('g')
                    .attr('class', 'node');
                
                nodeEnter.append('circle')
                    .attr('r', 12)
                    .attr('fill', d => this.getNodeColor(d))
                    .attr('stroke', '#fff')
                    .attr('stroke-width', 2);
                
                nodeEnter.append('text')
                    .attr('class', 'node-label')
                    .attr('dy', 20)
                    .text(d => this.getNodeLabel(d));
                
                const nodeUpdate = nodeEnter.merge(node);
                
                nodeUpdate.select('circle')
                    .attr('fill', d => this.getNodeColor(d))
                    .attr('r', d => this.getNodeSize(d));
                
                nodeUpdate
                    .on('mouseover', (event, d) => this.showTooltip(event, d))
                    .on('mouseout', () => this.hideTooltip());
                
                this.simulation.nodes(this.nodes);
                this.simulation.force('link').links(this.links);
                this.simulation.alpha(0.3).restart();
                
                this.simulation.on('tick', () => {
                    this.linkGroup.selectAll('.link')
                        .attr('x1', d => d.source.x)
                        .attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x)
                        .attr('y2', d => d.target.y);
                    
                    nodeUpdate
                        .attr('transform', d => `translate(${d.x},${d.y})`);
                });
            }
            
            getNodeColor(node) {
                if (node.threat_level > 50 || node.alert_count > 0) {
                    return '#ef4444';
                }
                if (node.host_type === 'router') {
                    return '#f59e0b';
                }
                if (node.is_internal) {
                    return '#10b981';
                }
                return '#3b82f6';
            }
            
            getNodeSize(node) {
                const baseSize = 12;
                if (node.threat_level > 50) return baseSize * 1.5;
                if (node.activity_level === 'high') return baseSize * 1.3;
                return baseSize;
            }
            
            getNodeLabel(node) {
                const parts = node.ip_address.split('.');
                if (parts.length === 4) {
                    return `${parts[2]}.${parts[3]}`;
                }
                return node.ip_address.substring(0, 8);
            }
            
            getLinkColor(link) {
                if (link.threat_score > 50) {
                    return '#ef4444';
                }
                switch (link.bandwidth_category) {
                    case 'high': return '#3b82f6';
                    case 'medium': return '#10b981';
                    default: return '#94a3b8';
                }
            }
            
            getLinkWidth(link) {
                switch (link.bandwidth_category) {
                    case 'high': return 3;
                    case 'medium': return 2;
                    default: return 1;
                }
            }
            
            showTooltip(event, node) {
                const content = `
                    <strong>${node.ip_address}</strong><br>
                    Type: ${node.host_type}<br>
                    Packets: ${node.packet_count}<br>
                    Activity: ${node.activity_level}<br>
                    Threat Level: ${node.threat_level}%<br>
                    Alerts: ${node.alert_count}
                    ${isTestMode ? '<br><span style="color: #f59e0b;">[TEST DATA]</span>' : ''}
                `;
                
                elements.tooltip.innerHTML = content;
                elements.tooltip.style.left = (event.pageX + 10) + 'px';
                elements.tooltip.style.top = (event.pageY - 10) + 'px';
                elements.tooltip.classList.add('show');
            }
            
            hideTooltip() {
                elements.tooltip.classList.remove('show');
            }
        }
        
        console.log('✅ Diagnostic JavaScript initialized');
    </script>
</body>
</html>'''

# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/interfaces')
def get_interfaces():
    interfaces = packet_capture.get_network_interfaces()
    return jsonify(interfaces)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_thread, is_capturing
    
    data = request.get_json()
    interface_ip = data.get('interface_ip')
    
    if is_capturing:
        return jsonify({'success': False, 'message': 'Capture already running'})
    
    # Clear previous data
    captured_packets.clear()
    alerts.clear()
    
    # Start capture with diagnostics
    success, message = packet_capture.start_capture(interface_ip)
    if success:
        is_capturing = True
        
        # Start real capture thread only if not in test mode
        if not packet_capture.generate_test_data:
            capture_thread = threading.Thread(target=packet_capture.capture_packets)
            capture_thread.daemon = True
            capture_thread.start()
        
        return jsonify({
            'success': True, 
            'message': message or 'Enhanced IDS started successfully',
            'test_mode': packet_capture.generate_test_data
        })
    else:
        return jsonify({'success': False, 'message': f'Failed to start: {message}'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing
    
    if not is_capturing:
        return jsonify({'success': False, 'message': 'No capture running'})
    
    is_capturing = False
    packet_capture.stop_capture()
    
    return jsonify({
        'success': True, 
        'message': 'Enhanced IDS stopped',
        'stats': packet_capture.packet_stats
    })

@app.route('/packets')
def get_packets():
    return jsonify(list(captured_packets)[-50:])

@app.route('/alerts')
def get_alerts():
    return jsonify(list(alerts))

@app.route('/topology')
def get_topology():
    try:
        topology_data = packet_capture.topology_tracker.get_topology_data()
        return jsonify(topology_data)
    except Exception as e:
        logger.error(f"Error getting topology: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/diagnostics')
def get_diagnostics():
    """Get system diagnostic information"""
    try:
        issues, solutions = check_system_requirements()
        
        # Get network interface details
        interfaces = packet_capture.get_network_interfaces()
        
        diagnostic_info = {
            'system_issues': issues,
            'solutions': solutions,
            'interfaces_available': len(interfaces),
            'interfaces': interfaces[:5],  # Show first 5
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'capture_stats': packet_capture.packet_stats,
            'test_mode': packet_capture.generate_test_data
        }
        
        return jsonify(diagnostic_info)
        
    except Exception as e:
        logger.error(f"Error getting diagnostics: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# WEBSOCKET HANDLERS
# =============================================================================

@socketio.on('connect')
def handle_connect():
    logger.info("🔌 Client connected")
    emit('connected', {
        'message': 'Connected to Diagnostic IDS server',
        'diagnostic_mode': True
    })
    
    # Send diagnostic information
    try:
        issues, solutions = check_system_requirements()
        if issues:
            diagnostic_message = f"⚠️ {len(issues)} system issues detected. Check console for details."
            emit('diagnostic_info', {'message': diagnostic_message})
    except Exception as e:
        logger.error(f"Error sending diagnostic info: {e}")

@socketio.on('request_topology')
def handle_topology_request():
    try:
        topology_data = packet_capture.topology_tracker.get_topology_data()
        emit('topology_update', topology_data)
    except Exception as e:
        logger.error(f"Error sending topology: {e}")

@socketio.on('request_diagnostics')
def handle_diagnostics_request():
    try:
        issues, solutions = check_system_requirements()
        diagnostic_info = {
            'issues': issues,
            'solutions': solutions,
            'timestamp': datetime.now().isoformat()
        }
        emit('diagnostic_info', diagnostic_info)
    except Exception as e:
        logger.error(f"Error sending diagnostics: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info("🔌 Client disconnected")

# =============================================================================
# MAIN APPLICATION
# =============================================================================

if __name__ == '__main__':
    print("=" * 80)
    print("🛡️  DIAGNOSTIC HIGH-PERFORMANCE IDS WITH TROUBLESHOOTING")
    print("=" * 80)
    print("This version includes comprehensive diagnostics to identify and resolve")
    print("packet capture issues. If real packet capture fails, it will automatically")
    print("fall back to test mode with simulated data.")
    print()
    print("Features:")
    print("• Automatic system requirement checking")
    print("• Raw socket capability testing")
    print("• Permission and privilege diagnostics")
    print("• Automatic fallback to test mode")
    print("• Real-time network topology visualization")
    print("• Simulated attack detection for testing")
    print("• Enhanced error reporting and solutions")
    print("=" * 80)
    print()
    
    # Run initial diagnostics
    print("🔍 Running initial system diagnostics...")
    issues, solutions = check_system_requirements()
    
    if issues:
        print(f"⚠️  Found {len(issues)} potential issues:")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")
        print()
        print("💡 Suggested solutions:")
        for i, solution in enumerate(solutions, 1):
            print(f"   {i}. {solution}")
        print()
        print("🔄 The system will attempt to run anyway and fall back to test mode if needed.")
    else:
        print("✅ All system requirements appear to be met!")
    
    print("=" * 80)
    print(f"🌐 Web Interface: http://localhost:5000")
    print("📊 The system will show either real or simulated data")
    print("🔧 Check the diagnostic panel for detailed system information")
    print("=" * 80)
    
    try:
        # Create debug log
        logger.info("🚀 Starting Diagnostic IDS System")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        logger.info(f"Python: {platform.python_version()}")
        
        socketio.run(app, debug=False, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
        
    except KeyboardInterrupt:
        print("\n👋 Diagnostic IDS shutdown requested")
        if is_capturing:
            packet_capture.stop_capture()
        print("✅ System stopped cleanly")
        
    except Exception as e:
        print(f"❌ Critical error: {e}")
        logger.error(f"Critical error: {e}", exc_info=True)
        if is_capturing:
            packet_capture.stop_capture()
        sys.exit(1)