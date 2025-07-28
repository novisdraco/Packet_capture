#!/usr/bin/env python3
"""
Enhanced Intrusion Detection System with YARA Integration
Clean, organized version with reduced false positives and smart detection
"""

# Core imports
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import socket
import struct
import threading
import sys
import psutil
import ipaddress
from datetime import datetime
import json
import time

# YARA integration (optional)
try:
    from yara_ids import YARAEngine, YARAIDSRule, integrate_yara_into_ids, create_enhanced_alert
    YARA_AVAILABLE = True
    print("✅ YARA integration loaded successfully")
except ImportError as e:
    print(f"⚠️  YARA not available: {e}")
    print("💡 Install YARA: pip install yara-python")
    YARA_AVAILABLE = False

# Flask application setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'enhanced_ids_security_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global configuration
CONFIG = {
    'max_packets': 1000,
    'max_alerts': 100,
    'environment': 'balanced',  # home, balanced, enterprise, server
    'debug_mode': True
}

# Global variables
capture_thread = None
is_capturing = False
captured_packets = []
alerts = []

# =============================================================================
# BASE CLASSES
# =============================================================================

class IDSRule:
    """Base class for all IDS detection rules"""
    def __init__(self, name, description, severity="Medium"):
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = True
        self.trigger_count = 0
        self.last_triggered = None
    
    def check(self, packet_info, raw_data=None):
        """Override this method in rule implementations"""
        return False
    
    def get_alert_message(self, packet_info):
        """Get alert message for this rule"""
        return f"{self.name}: {self.description}"
    
    def trigger(self):
        """Mark rule as triggered"""
        self.trigger_count += 1
        self.last_triggered = datetime.now()

# =============================================================================
# DETECTION RULES
# =============================================================================

class SuspiciousPortScanRule(IDSRule):
    """Enhanced port scan detection with smart filtering"""
    def __init__(self):
        super().__init__(
            name="Port Scan Detected",
            description="Multiple connection attempts to different ports",
            severity="High"
        )
        self.port_attempts = {}
        self.time_window = 60
        self.threshold = 25  # Balanced threshold
        
        # Legitimate ports that don't count toward port scanning
        self.legitimate_ports = {
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 
            587, 993, 995, 8080, 8443, 3389, 5900
        }
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'TCP':
            return False
        
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        current_time = time.time()
        
        # Skip legitimate ports
        if dst_port in self.legitimate_ports:
            return False
        
        # Skip private networks
        if self._is_private_ip(src_ip):
            return False
        
        if src_ip and dst_port:
            if src_ip not in self.port_attempts:
                self.port_attempts[src_ip] = []
            
            self.port_attempts[src_ip].append({
                'port': dst_port,
                'time': current_time
            })
            
            # Clean old entries
            self.port_attempts[src_ip] = [
                attempt for attempt in self.port_attempts[src_ip]
                if current_time - attempt['time'] <= self.time_window
            ]
            
            # Check threshold
            unique_ports = set(attempt['port'] for attempt in self.port_attempts[src_ip])
            return len(unique_ports) >= self.threshold
        
        return False
    
    def _is_private_ip(self, ip_str):
        """Check if IP is private/internal"""
        if not ip_str:
            return True
        return (ip_str.startswith('127.') or 
                ip_str.startswith('192.168.') or 
                ip_str.startswith('10.') or
                ip_str.startswith('172.16.'))

class EnhancedDDoSDetectionRule(IDSRule):
    """Enhanced DDoS detection with minimal false positives"""
    def __init__(self):
        super().__init__(
            name="DDoS Attack Detected",
            description="High volume traffic from single source",
            severity="High"
        )
        self.packet_counts = {}
        self.connection_counts = {}
        self.time_window = 60  # 1 minute observation
        self.threshold = 800   # Much higher threshold
        self.connection_threshold = 150
        
        # Whitelist for legitimate sources
        self.whitelist_ranges = self._initialize_whitelist()
        
        # Protocol-specific thresholds
        self.protocol_thresholds = {
            'TCP': 800,
            'UDP': 400,
            'ICMP': 100
        }
        
        # High-traffic ports (web, email, DNS)
        self.high_traffic_ports = {53, 80, 443, 25, 110, 143, 993, 995}
    
    def _initialize_whitelist(self):
        """Initialize IP whitelist ranges"""
        try:
            return [
                ipaddress.IPv4Network('127.0.0.0/8'),     # Localhost
                ipaddress.IPv4Network('10.0.0.0/8'),      # Private
                ipaddress.IPv4Network('172.16.0.0/12'),   # Private
                ipaddress.IPv4Network('192.168.0.0/16'),  # Private
                ipaddress.IPv4Network('8.8.8.0/24'),      # Google DNS
                ipaddress.IPv4Network('1.1.1.0/24'),      # Cloudflare
                ipaddress.IPv4Network('208.67.222.0/24'), # OpenDNS
            ]
        except Exception:
            return []
    
    def _is_whitelisted(self, ip_str):
        """Check if IP is whitelisted"""
        if not ip_str:
            return True
        
        # Fallback check if ipaddress not available
        if not self.whitelist_ranges:
            return (ip_str.startswith('127.') or 
                   ip_str.startswith('192.168.') or 
                   ip_str.startswith('10.'))
        
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return any(ip in network for network in self.whitelist_ranges)
        except Exception:
            return ip_str.startswith(('127.', '192.168.', '10.'))
    
    def _get_dynamic_threshold(self, protocol, dst_port):
        """Calculate dynamic threshold based on protocol and port"""
        base_threshold = self.protocol_thresholds.get(protocol, self.threshold)
        
        # Double threshold for high-traffic ports
        if dst_port and dst_port in self.high_traffic_ports:
            base_threshold *= 2
        
        return base_threshold
    
    def check(self, packet_info, raw_data=None):
        src_ip = packet_info.get('src_ip')
        protocol = packet_info.get('protocol', 'Unknown')
        dst_port = packet_info.get('dst_port', 0)
        current_time = time.time()
        
        if not src_ip or self._is_whitelisted(src_ip):
            return False
        
        # Initialize tracking
        if src_ip not in self.packet_counts:
            self.packet_counts[src_ip] = []
            self.connection_counts[src_ip] = []
        
        # Track packets
        self.packet_counts[src_ip].append(current_time)
        
        # Track new connections (TCP SYN)
        flags = packet_info.get('flags', '')
        if protocol == 'TCP' and 'SYN' in flags and 'ACK' not in flags:
            self.connection_counts[src_ip].append(current_time)
        
        # Clean old entries
        self.packet_counts[src_ip] = [
            ts for ts in self.packet_counts[src_ip]
            if current_time - ts <= self.time_window
        ]
        self.connection_counts[src_ip] = [
            ts for ts in self.connection_counts[src_ip]
            if current_time - ts <= self.time_window
        ]
        
        # Calculate metrics
        packet_count = len(self.packet_counts[src_ip])
        connection_count = len(self.connection_counts[src_ip])
        dynamic_threshold = self._get_dynamic_threshold(protocol, dst_port)
        
        # Detection logic with multiple validations
        if packet_count >= dynamic_threshold or connection_count >= self.connection_threshold:
            # Calculate rate (packets per minute)
            rate = packet_count / (self.time_window / 60)
            
            # Ignore low-rate traffic
            if rate < 100:
                return False
            
            # Check for distributed attack (many high-traffic IPs = busy server)
            high_traffic_ips = sum(
                1 for ip_packets in self.packet_counts.values()
                if len(ip_packets) > dynamic_threshold * 0.3
            )
            
            if high_traffic_ips > 15:  # Busy server scenario
                return False
            
            # Final validation
            return (packet_count >= dynamic_threshold and rate > 200) or \
                   (connection_count >= self.connection_threshold and connection_count > 100)
        
        return False

class SmartBruteForceRule(IDSRule):
    """Smart brute force detection for authentication services"""
    def __init__(self):
        super().__init__(
            name="Brute Force Attack Detected",
            description="Multiple authentication attempts detected",
            severity="High"
        )
        self.connection_attempts = {}
        self.time_window = 300  # 5 minutes
        self.threshold = 50
        
        # Only actual authentication ports
        self.auth_ports = {22, 23, 21, 3389, 5900, 1433, 3306, 5432}
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'TCP':
            return False
        
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Only check authentication ports
        if dst_port not in self.auth_ports:
            return False
        
        # Skip localhost
        if src_ip and src_ip.startswith('127.'):
            return False
        
        if src_ip:
            key = f"{src_ip}:{dst_port}"
            
            if key not in self.connection_attempts:
                self.connection_attempts[key] = []
            
            self.connection_attempts[key].append(current_time)
            
            # Clean old entries
            self.connection_attempts[key] = [
                ts for ts in self.connection_attempts[key]
                if current_time - ts <= self.time_window
            ]
            
            return len(self.connection_attempts[key]) >= self.threshold
        
        return False

class DNSTunnelingRule(IDSRule):
    """DNS tunneling detection with enhanced accuracy"""
    def __init__(self):
        super().__init__(
            name="DNS Tunneling Detected",
            description="Suspicious DNS query patterns detected",
            severity="High"
        )
        self.dns_queries = {}
        self.time_window = 60
        self.threshold = 120  # Higher threshold
    
    def check(self, packet_info, raw_data=None):
        if not (packet_info.get('protocol') == 'UDP' and 
                packet_info.get('dst_port') == 53):
            return False
        
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Skip localhost DNS
        if src_ip and src_ip.startswith('127.'):
            return False
        
        if src_ip:
            if src_ip not in self.dns_queries:
                self.dns_queries[src_ip] = []
            
            self.dns_queries[src_ip].append(current_time)
            
            # Clean old entries
            self.dns_queries[src_ip] = [
                ts for ts in self.dns_queries[src_ip]
                if current_time - ts <= self.time_window
            ]
            
            return len(self.dns_queries[src_ip]) >= self.threshold
        
        return False

class LargePacketRule(IDSRule):
    """Large packet detection for potential attacks"""
    def __init__(self):
        super().__init__(
            name="Large Packet Detected",
            description="Unusually large packet detected",
            severity="Medium"
        )
        self.size_threshold = 8000  # 8KB threshold
    
    def check(self, packet_info, raw_data=None):
        return packet_info.get('size', 0) > self.size_threshold

class SuspiciousPayloadRule(IDSRule):
    """Payload-based threat detection"""
    def __init__(self):
        super().__init__(
            name="Suspicious Payload Detected",
            description="Malicious payload patterns found",
            severity="High"
        )
        self.malicious_patterns = [
            b'cmd.exe', b'/bin/sh', b'powershell',
            b'SELECT * FROM', b'UNION SELECT',
            b'<script>', b'javascript:', b'eval(',
            b'system(', b'exec('
        ]
    
    def check(self, packet_info, raw_data=None):
        if not raw_data or len(raw_data) <= 40:
            return False
        
        payload = raw_data[40:].lower()
        
        # Skip very large payloads (file transfers)
        if len(payload) > 10000:
            return False
        
        return any(pattern in payload for pattern in self.malicious_patterns)

class NetworkReconRule(IDSRule):
    """Network reconnaissance detection"""
    def __init__(self):
        super().__init__(
            name="Network Reconnaissance Detected",
            description="ICMP reconnaissance activity detected",
            severity="Medium"
        )
        self.icmp_requests = {}
        self.time_window = 60
        self.threshold = 60  # Higher threshold
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'ICMP':
            return False
        
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Skip localhost ICMP
        if src_ip and src_ip.startswith('127.'):
            return False
        
        if src_ip:
            if src_ip not in self.icmp_requests:
                self.icmp_requests[src_ip] = []
            
            self.icmp_requests[src_ip].append(current_time)
            
            # Clean old entries
            self.icmp_requests[src_ip] = [
                ts for ts in self.icmp_requests[src_ip]
                if current_time - ts <= self.time_window
            ]
            
            return len(self.icmp_requests[src_ip]) >= self.threshold
        
        return False

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

class IDSConfigManager:
    """Configuration manager for different environments"""
    
    @staticmethod
    def configure_rules_for_environment(rules, environment="balanced"):
        """Configure rules based on environment type"""
        
        if environment == "home":
            # Home/small office - more sensitive
            for rule in rules:
                if isinstance(rule, EnhancedDDoSDetectionRule):
                    rule.threshold = 400
                    rule.time_window = 45
                elif isinstance(rule, SuspiciousPortScanRule):
                    rule.threshold = 15
                elif isinstance(rule, DNSTunnelingRule):
                    rule.threshold = 80
        
        elif environment == "enterprise":
            # Enterprise - less sensitive
            for rule in rules:
                if isinstance(rule, EnhancedDDoSDetectionRule):
                    rule.threshold = 1200
                    rule.time_window = 90
                elif isinstance(rule, SuspiciousPortScanRule):
                    rule.threshold = 35
                elif isinstance(rule, DNSTunnelingRule):
                    rule.threshold = 150
        
        elif environment == "server":
            # Public server - least sensitive
            for rule in rules:
                if isinstance(rule, EnhancedDDoSDetectionRule):
                    rule.threshold = 2000
                    rule.time_window = 120
                elif isinstance(rule, SuspiciousPortScanRule):
                    rule.threshold = 50
                elif isinstance(rule, DNSTunnelingRule):
                    rule.threshold = 200
        
        print(f"🔧 IDS configured for '{environment}' environment")

# =============================================================================
# IDS ENGINE
# =============================================================================

class EnhancedIDSEngine:
    """Main IDS engine with YARA support"""
    def __init__(self, environment="balanced"):
        print("🛡️ Initializing Enhanced IDS Engine...")
        
        # Initialize detection rules
        self.rules = [
            SuspiciousPortScanRule(),
            EnhancedDDoSDetectionRule(),
            SmartBruteForceRule(),
            DNSTunnelingRule(),
            LargePacketRule(),
            SuspiciousPayloadRule(),
            NetworkReconRule()
        ]
        
        # Configure for environment
        IDSConfigManager.configure_rules_for_environment(self.rules, environment)
        
        self.total_alerts = 0
        self.yara_engine = None
        
        # Initialize YARA if available
        if YARA_AVAILABLE:
            try:
                self.yara_engine = integrate_yara_into_ids(self)
                print("🔍 YARA engine initialized")
            except Exception as e:
                print(f"❌ YARA initialization failed: {e}")
                self.yara_engine = None
        
        self._print_initialization_summary()
    
    def _print_initialization_summary(self):
        """Print initialization summary"""
        print(f"📊 IDS Engine Ready:")
        print(f"   • {len(self.rules)} detection rules loaded")
        print(f"   • Environment: {CONFIG['environment']}")
        print(f"   • YARA: {'Available' if self.yara_engine else 'Not available'}")
        
        for rule in self.rules:
            print(f"   • {rule.name} ({rule.severity})")
    
    def analyze_packet(self, packet_info, raw_data=None):
        """Analyze packet against all detection rules"""
        triggered_alerts = []
        
        for rule in self.rules:
            if rule.enabled and rule.check(packet_info, raw_data):
                rule.trigger()
                
                alert = {
                    'id': self.total_alerts + len(triggered_alerts) + 1,
                    'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    'rule_name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity,
                    'detection_type': 'Traditional',
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'src_port': packet_info.get('src_port'),
                    'dst_port': packet_info.get('dst_port'),
                    'protocol': packet_info.get('protocol'),
                    'packet_size': packet_info.get('size'),
                    'packet_id': packet_info.get('id')
                }
                
                # Enhanced alert for YARA rules
                if hasattr(rule, 'yara_engine') and 'yara_matches' in packet_info:
                    alert = create_enhanced_alert(alert, packet_info['yara_matches'])
                    alert['yara_details'] = packet_info['yara_matches']
                
                triggered_alerts.append(alert)
        
        self.total_alerts += len(triggered_alerts)
        return triggered_alerts
    
    def get_rules_status(self):
        """Get status of all rules"""
        rule_status = []
        
        for rule in self.rules:
            status = {
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'trigger_count': rule.trigger_count,
                'last_triggered': rule.last_triggered.strftime("%H:%M:%S") if rule.last_triggered else None,
                'type': 'YARA' if hasattr(rule, 'yara_engine') else 'Traditional'
            }
            rule_status.append(status)
        
        # Add YARA statistics if available
        if self.yara_engine:
            yara_stats = self.yara_engine.get_statistics()
            rule_status.append({
                'name': 'YARA Engine Statistics',
                'description': f"Total: {yara_stats['total_rules']}, Enabled: {yara_stats['enabled_rules']}, Matches: {yara_stats['total_matches']}",
                'severity': 'Info',
                'enabled': True,
                'trigger_count': yara_stats['total_matches'],
                'type': 'YARA Statistics'
            })
        
        return rule_status
    
    def get_yara_statistics(self):
        """Get YARA engine statistics"""
        if self.yara_engine:
            return self.yara_engine.get_statistics()
        return {'error': 'YARA engine not available'}

# =============================================================================
# PACKET CAPTURE
# =============================================================================

class PacketCapture:
    """Enhanced packet capture with smart analysis"""
    def __init__(self):
        self.conn = None
        self.is_running = False
        self.ids_engine = EnhancedIDSEngine(CONFIG['environment'])
        self.packet_stats = {
            'total_packets': 0,
            'total_alerts': 0,
            'start_time': None
        }
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        try:
            for interface_name, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            'name': interface_name,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
            
            if CONFIG['debug_mode']:
                print(f"📡 Found {len(interfaces)} network interfaces")
                
        except Exception as e:
            print(f"❌ Error getting interfaces: {e}")
        
        return interfaces
    
    def start_capture(self, interface_ip):
        """Start packet capture on specified interface"""
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.conn.bind((interface_ip, 0))
            self.conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if sys.platform == "win32":
                self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.is_running = True
            self.packet_stats['start_time'] = datetime.now()
            
            print(f"🚀 Packet capture started on {interface_ip}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start capture: {e}")
            return False, str(e)
    
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
        
        print("⏹️ Packet capture stopped")
    
    def capture_packets(self):
        """Main packet capture loop"""
        global captured_packets, alerts
        
        print("🔍 Starting packet analysis...")
        
        while self.is_running:
            try:
                raw_data, addr = self.conn.recvfrom(65535)
                self.packet_stats['total_packets'] += 1
                
                # Parse packet
                packet_info = self.parse_packet(raw_data, self.packet_stats['total_packets'])
                
                # IDS analysis
                packet_alerts = self.ids_engine.analyze_packet(packet_info, raw_data)
                
                # Handle alerts
                for alert in packet_alerts:
                    alerts.append(alert)
                    self.packet_stats['total_alerts'] += 1
                    
                    if len(alerts) > CONFIG['max_alerts']:
                        alerts.pop(0)
                    
                    # Emit to web interface
                    socketio.emit('new_alert', alert)
                    
                    if CONFIG['debug_mode']:
                        print(f"🚨 Alert: {alert['rule_name']} from {alert['src_ip']}")
                
                # Store packet
                captured_packets.append(packet_info)
                if len(captured_packets) > CONFIG['max_packets']:
                    captured_packets.pop(0)
                
                # Emit to web interface
                socketio.emit('new_packet', packet_info)
                
            except Exception as e:
                if self.is_running:
                    print(f"❌ Capture error: {e}")
                    socketio.emit('capture_error', {'error': str(e)})
                break
    
    def parse_packet(self, data, packet_num):
        """Parse raw packet data"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Parse IP header
        ip_header = self.parse_ip_header(data)
        
        packet_info = {
            'id': packet_num,
            'timestamp': timestamp,
            'src_ip': ip_header['src_ip'],
            'dst_ip': ip_header['dst_ip'],
            'protocol': self.get_protocol_name(ip_header['protocol']),
            'protocol_num': ip_header['protocol'],
            'size': len(data),
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'payload': None
        }
        
        # Parse transport layer
        try:
            if ip_header['protocol'] == 6:  # TCP
                tcp_info = self.parse_tcp_header(data[ip_header['header_length']:])
                packet_info.update(tcp_info)
            elif ip_header['protocol'] == 17:  # UDP
                udp_info = self.parse_udp_header(data[ip_header['header_length']:])
                packet_info.update(udp_info)
        except Exception:
            pass  # Continue with basic packet info
        
        # Get payload preview
        try:
            payload_start = ip_header['header_length']
            if ip_header['protocol'] in [6, 17]:
                payload_start += 8
            
            if payload_start < len(data):
                payload = data[payload_start:payload_start+32]
                packet_info['payload'] = ' '.join(f'{byte:02x}' for byte in payload)
        except Exception:
            pass
        
        return packet_info
    
    def parse_ip_header(self, data):
        """Parse IP header"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = ip_header[0]
        ihl = version_ihl & 0xF
        header_length = ihl * 4
        
        return {
            'header_length': header_length,
            'protocol': ip_header[6],
            'src_ip': socket.inet_ntoa(ip_header[8]),
            'dst_ip': socket.inet_ntoa(ip_header[9])
        }
    
    def parse_tcp_header(self, data):
        """Parse TCP header"""
        if len(data) < 20:
            return {'src_port': 0, 'dst_port': 0, 'flags': 'Invalid'}
        
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        flags = tcp_header[5]
        
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        
        return {
            'src_port': tcp_header[0],
            'dst_port': tcp_header[1],
            'flags': ','.join(flag_names) if flag_names else 'None'
        }
    
    def parse_udp_header(self, data):
        """Parse UDP header"""
        if len(data) < 8:
            return {'src_port': 0, 'dst_port': 0}
        
        udp_header = struct.unpack('!HHHH', data[:8])
        return {
            'src_port': udp_header[0],
            'dst_port': udp_header[1]
        }
    
    def get_protocol_name(self, protocol_num):
        """Convert protocol number to name"""
        protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 
            2: 'IGMP', 89: 'OSPF'
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

# =============================================================================
# WEB APPLICATION ROUTES
# =============================================================================

# Initialize packet capture
packet_capture = PacketCapture()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/interfaces')
def get_interfaces():
    """Get available network interfaces"""
    interfaces = packet_capture.get_network_interfaces()
    return jsonify(interfaces)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_thread, is_capturing, captured_packets, alerts
    
    data = request.get_json()
    interface_ip = data.get('interface_ip')
    
    if is_capturing:
        return jsonify({'success': False, 'message': 'Capture already running'})
    
    # Clear previous data
    captured_packets.clear()
    alerts.clear()
    
    # Start capture
    result = packet_capture.start_capture(interface_ip)
    if result is True:
        is_capturing = True
        capture_thread = threading.Thread(target=packet_capture.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        status = "with YARA support" if YARA_AVAILABLE else "traditional rules only"
        return jsonify({
            'success': True, 
            'message': f'Enhanced IDS started {status}',
            'environment': CONFIG['environment']
        })
    else:
        return jsonify({'success': False, 'message': f'Failed to start: {result[1]}'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
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
    """Get captured packets"""
    return jsonify(captured_packets)

@app.route('/alerts')
def get_alerts():
    """Get security alerts"""
    return jsonify(alerts)

@app.route('/rules')
def get_rules():
    """Get IDS rules status"""
    return jsonify(packet_capture.ids_engine.get_rules_status())

@app.route('/stats')
def get_stats():
    """Get IDS statistics"""
    stats = {
        'packet_stats': packet_capture.packet_stats,
        'config': CONFIG,
        'rules_count': len(packet_capture.ids_engine.rules),
        'active_rules': sum(1 for rule in packet_capture.ids_engine.rules if rule.enabled),
        'yara_available': YARA_AVAILABLE
    }
    return jsonify(stats)

# YARA-specific routes
@app.route('/yara/stats')
def get_yara_stats():
    """Get YARA engine statistics"""
    return jsonify(packet_capture.ids_engine.get_yara_statistics())

@app.route('/yara/rules')
def get_yara_rules():
    """Get YARA rules details"""
    if packet_capture.ids_engine.yara_engine:
        stats = packet_capture.ids_engine.yara_engine.get_statistics()
        return jsonify(stats.get('rule_details', []))
    return jsonify({'error': 'YARA engine not available'})

@app.route('/yara/toggle/<rule_name>', methods=['POST'])
def toggle_yara_rule(rule_name):
    """Toggle YARA rule on/off"""
    if not packet_capture.ids_engine.yara_engine:
        return jsonify({'success': False, 'message': 'YARA engine not available'})
    
    yara_engine = packet_capture.ids_engine.yara_engine
    
    if hasattr(yara_engine, 'rules') and rule_name in yara_engine.rules:
        rule = yara_engine.rules[rule_name]
        rule.enabled = not rule.enabled
        status = "enabled" if rule.enabled else "disabled"
        return jsonify({'success': True, 'message': f'YARA rule {rule_name} {status}'})
    
    return jsonify({'success': False, 'message': f'YARA rule {rule_name} not found'})

# =============================================================================
# WEBSOCKET HANDLERS
# =============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    status = "with YARA support" if YARA_AVAILABLE else "(YARA not available)"
    emit('connected', {
        'message': f'Connected to Enhanced IDS server {status}',
        'environment': CONFIG['environment'],
        'rules_count': len(packet_capture.ids_engine.rules)
    })
    
    # Send recent data to new client
    for packet in captured_packets[-20:]:
        emit('new_packet', packet)
    for alert in alerts[-10:]:
        emit('new_alert', alert)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass

# =============================================================================
# MAIN APPLICATION
# =============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("🛡️  ENHANCED INTRUSION DETECTION SYSTEM")
    print("=" * 70)
    print("Features:")
    print("• Real-time packet capture and analysis")
    print("• Smart detection rules with reduced false positives")
    print("• Protocol-aware and environment-specific thresholds")
    if YARA_AVAILABLE:
        print("• YARA pattern matching and malware detection")
        print("• Advanced payload analysis")
    else:
        print("• YARA support: Not available (install yara-python)")
    print("• Web-based monitoring interface")
    print("• Intelligent IP whitelisting")
    print("• Configurable detection sensitivity")
    print("=" * 70)
    print(f"🌐 Web Interface: http://localhost:5000")
    print(f"🔧 Environment: {CONFIG['environment']}")
    print(f"📊 Rules loaded: {len(packet_capture.ids_engine.rules)}")
    print("⚠️  Remember to run as Administrator/sudo for packet capture!")
    print("=" * 70)
    
    try:
        socketio.run(app, debug=CONFIG['debug_mode'], host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 IDS shutdown requested")
        if is_capturing:
            packet_capture.stop_capture()
        print("✅ Enhanced IDS stopped cleanly")
    except Exception as e:
        print(f"❌ Critical error: {e}")
        if is_capturing:
            packet_capture.stop_capture()





