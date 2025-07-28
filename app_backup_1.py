





















            #!/usr/bin/env python3
"""
Enhanced Intrusion Detection System with YARA Integration
Web interface with rule-based threat detection, YARA pattern matching, and alerting
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import socket
import struct
import threading
import sys
import psutil
from datetime import datetime
import json
import re
import time

# Import YARA integration (save the previous artifact as yara_ids.py)
try:
    from yara_ids import YARAEngine, YARAIDSRule, integrate_yara_into_ids, create_enhanced_alert
    YARA_AVAILABLE = True
    print("✅ YARA integration loaded successfully")
except ImportError as e:
    print(f"⚠️  YARA not available: {e}")
    print("💡 Install YARA: pip install yara-python")
    YARA_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet_capture_ids_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
capture_thread = None
is_capturing = False
captured_packets = []
alerts = []
max_packets = 1000
max_alerts = 100

class IDSRule:
    """Base class for IDS rules"""
    def __init__(self, name, description, severity="Medium"):
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = True
        self.trigger_count = 0
    
    def check(self, packet_info, raw_data=None):
        """Override this method in rule implementations"""
        return False
    
    def get_alert_message(self, packet_info):
        """Get alert message for this rule"""
        return f"{self.name}: {self.description}"

class SuspiciousPortScanRule(IDSRule):
    """Rule to detect potential port scanning"""
    def __init__(self):
        super().__init__(
            name="Potential Port Scan Detected",
            description="Multiple connection attempts to different ports from same source",
            severity="High"
        )
        self.port_attempts = {}  # Track connection attempts
        self.time_window = 60  # 60 seconds
        self.threshold = 20  # INCREASED: 20 different ports (was 10) - more realistic
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'TCP':
            return False
        
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        current_time = time.time()
        
        # Skip common legitimate ports to reduce false positives
        legitimate_ports = {80, 443, 53, 25, 110, 143, 993, 995, 587}
        if dst_port in legitimate_ports:
            return False
        
        if src_ip and dst_port:
            if src_ip not in self.port_attempts:
                self.port_attempts[src_ip] = []
            
            # Add current attempt
            self.port_attempts[src_ip].append({
                'port': dst_port,
                'time': current_time
            })
            
            # Clean old entries
            self.port_attempts[src_ip] = [
                attempt for attempt in self.port_attempts[src_ip]
                if current_time - attempt['time'] <= self.time_window
            ]
            
            # Check for threshold
            unique_ports = set(attempt['port'] for attempt in self.port_attempts[src_ip])
            if len(unique_ports) >= self.threshold:
                return True
        
        return False

class LargePacketRule(IDSRule):
    """Rule to detect unusually large packets"""
    def __init__(self):
        super().__init__(
            name="Large Packet Detected",
            description="Packet size exceeds normal threshold",
            severity="Medium"
        )
        self.size_threshold = 8000  # INCREASED: 8KB (was 1.5KB) - more realistic for modern networks
    
    def check(self, packet_info, raw_data=None):
        return packet_info.get('size', 0) > self.size_threshold

class DDoSDetectionRule(IDSRule):
    """Rule to detect potential DDoS attacks"""
    def __init__(self):
        super().__init__(
            name="DDoS Attack Detected",
            description="High volume of packets from single source",
            severity="High"
        )
        self.packet_counts = {}
        self.time_window = 30  # INCREASED: 30 seconds (was 10) - longer observation window
        self.threshold = 200   # INCREASED: 200 packets in 30 seconds (was 50 in 10) - much higher threshold
    
    def check(self, packet_info, raw_data=None):
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Skip localhost traffic to avoid false positives
        if src_ip and src_ip.startswith('127.'):
            return False
        
        if src_ip:
            if src_ip not in self.packet_counts:
                self.packet_counts[src_ip] = []
            
            # Add current timestamp
            self.packet_counts[src_ip].append(current_time)
            
            # Clean old entries
            self.packet_counts[src_ip] = [
                timestamp for timestamp in self.packet_counts[src_ip]
                if current_time - timestamp <= self.time_window
            ]
            
            # Check threshold
            if len(self.packet_counts[src_ip]) >= self.threshold:
                return True
        
        return False

class BruteForceRule(IDSRule):
    """Rule to detect brute force attacks on common services"""
    def __init__(self):
        super().__init__(
            name="Brute Force Attack Detected",
            description="Multiple connection attempts to authentication services",
            severity="High"
        )
        self.connection_attempts = {}
        self.time_window = 300  # INCREASED: 5 minutes (was 1 minute) - longer observation
        self.threshold = 50     # INCREASED: 50 attempts in 5 minutes (was 10 in 1 minute)
        # REDUCED target ports - only authentication services, not web traffic
        self.target_ports = [22, 23, 21, 3389, 5900]  # SSH, Telnet, FTP, RDP, VNC only
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'TCP':
            return False
        
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Skip localhost traffic
        if src_ip and src_ip.startswith('127.'):
            return False
        
        if dst_port in self.target_ports and src_ip:
            key = f"{src_ip}:{dst_port}"
            
            if key not in self.connection_attempts:
                self.connection_attempts[key] = []
            
            self.connection_attempts[key].append(current_time)
            
            # Clean old entries
            self.connection_attempts[key] = [
                timestamp for timestamp in self.connection_attempts[key]
                if current_time - timestamp <= self.time_window
            ]
            
            # Check threshold
            if len(self.connection_attempts[key]) >= self.threshold:
                return True
        
        return False

class DNSTunnelingRule(IDSRule):
    """Rule to detect potential DNS tunneling"""
    def __init__(self):
        super().__init__(
            name="DNS Tunneling Detected",
            description="Unusual DNS query patterns suggesting data exfiltration",
            severity="High"
        )
        self.dns_queries = {}
        self.time_window = 60   # INCREASED: 60 seconds (was 30)
        self.threshold = 100    # INCREASED: 100 DNS queries per minute (was 20 in 30 seconds)
    
    def check(self, packet_info, raw_data=None):
        if (packet_info.get('protocol') == 'UDP' and 
            packet_info.get('dst_port') == 53):  # DNS port
            
            src_ip = packet_info.get('src_ip')
            current_time = time.time()
            
            # Skip localhost DNS queries
            if src_ip and src_ip.startswith('127.'):
                return False
            
            if src_ip:
                if src_ip not in self.dns_queries:
                    self.dns_queries[src_ip] = []
                
                self.dns_queries[src_ip].append(current_time)
                
                # Clean old entries
                self.dns_queries[src_ip] = [
                    timestamp for timestamp in self.dns_queries[src_ip]
                    if current_time - timestamp <= self.time_window
                ]
                
                # Check threshold
                if len(self.dns_queries[src_ip]) >= self.threshold:
                    return True
        
        return False

class SuspiciousPayloadRule(IDSRule):
    """Rule to detect suspicious payload patterns"""
    def __init__(self):
        super().__init__(
            name="Suspicious Payload Pattern",
            description="Packet contains potentially malicious payload signatures",
            severity="High"
        )
        # Common malicious patterns (simplified)
        self.malicious_patterns = [
            b'cmd.exe',
            b'/bin/sh',
            b'powershell',
            b'SELECT * FROM',
            b'UNION SELECT',
            b'<script>',
            b'javascript:',
            b'eval(',
            b'system(',
            b'exec(',
        ]
    
    def check(self, packet_info, raw_data=None):
        if raw_data and len(raw_data) > 40:  # Skip headers
            payload = raw_data[40:].lower()
            
            # Only check payloads that are reasonably sized (avoid large file transfers)
            if len(payload) > 10000:  # Skip very large payloads
                return False
            
            for pattern in self.malicious_patterns:
                if pattern in payload:
                    return True
        
        return False

class NetworkReconRule(IDSRule):
    """Rule to detect network reconnaissance activities"""
    def __init__(self):
        super().__init__(
            name="Network Reconnaissance Detected",
            description="ICMP ping sweeps or network mapping attempts",
            severity="Medium"
        )
        self.icmp_requests = {}
        self.time_window = 60   # INCREASED: 60 seconds (was 20)
        self.threshold = 50     # INCREASED: 50 ICMP requests in 60 seconds (was 10 in 20)
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') == 'ICMP':
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
                    timestamp for timestamp in self.icmp_requests[src_ip]
                    if current_time - timestamp <= self.time_window
                ]
                
                # Check threshold
                if len(self.icmp_requests[src_ip]) >= self.threshold:
                    return True
        
        return False

class EnhancedIDSEngine:
    """Enhanced Intrusion Detection System Engine with YARA support"""
    def __init__(self):
        # Initialize traditional rules
        self.rules = [
            SuspiciousPortScanRule(),
            LargePacketRule(),
            DDoSDetectionRule(),
            BruteForceRule(),
            DNSTunnelingRule(),
            SuspiciousPayloadRule(),
            NetworkReconRule()
        ]
        
        self.total_alerts = 0
        self.yara_engine = None
        
        # Initialize YARA if available
        if YARA_AVAILABLE:
            try:
                self.yara_engine = integrate_yara_into_ids(self)
                print("🔍 YARA engine initialized successfully")
            except Exception as e:
                print(f"❌ Failed to initialize YARA: {e}")
                self.yara_engine = None
        else:
            print("⚠️ YARA engine not available - continuing with traditional rules only")
        
        print(f"🛡️ Enhanced IDS Engine initialized with {len(self.rules)} rules")
        self.print_rule_summary()
    
    def print_rule_summary(self):
        """Print summary of loaded rules"""
        print("📊 Rule Summary:")
        for rule in self.rules:
            rule_type = "YARA" if hasattr(rule, 'yara_engine') else "Traditional"
            print(f"   • {rule.name} ({rule.severity}) [{rule_type}]")
        
        if self.yara_engine:
            yara_stats = self.yara_engine.get_statistics()
            print(f"   • YARA Rules: {yara_stats['enabled_rules']} enabled, {yara_stats['disabled_rules']} disabled")
    
    def add_rule(self, rule):
        """Add a new rule to the IDS"""
        self.rules.append(rule)
    
    def analyze_packet(self, packet_info, raw_data=None):
        """Analyze packet against all rules including YARA"""
        triggered_alerts = []
        
        # Check traditional rules first
        for rule in self.rules:
            if rule.enabled and rule.check(packet_info, raw_data):
                rule.trigger_count += 1
                
                # Create base alert
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
        """Get status of all rules including YARA statistics"""
        rule_status = []
        
        for rule in self.rules:
            status = {
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'trigger_count': rule.trigger_count,
                'type': 'YARA' if hasattr(rule, 'yara_engine') else 'Traditional'
            }
            rule_status.append(status)
        
        # Add YARA engine statistics if available
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
        """Get detailed YARA statistics"""
        if self.yara_engine:
            return self.yara_engine.get_statistics()
        return {'error': 'YARA engine not available'}

class PacketCapture:
    def __init__(self):
        self.conn = None
        self.is_running = False
        self.ids_engine = EnhancedIDSEngine()
        
    def get_network_interfaces(self):
        """Get list of available network interfaces"""
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
        except Exception as e:
            print(f"Error getting interfaces: {e}")
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
            return True
        except Exception as e:
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
    
    def capture_packets(self):
        """Capture packets and analyze with enhanced IDS"""
        global captured_packets, is_capturing, alerts
        packet_count = 0
        
        while self.is_running:
            try:
                raw_data, addr = self.conn.recvfrom(65535)
                packet_count += 1
                
                # Parse packet
                packet_info = self.parse_packet(raw_data, packet_count)
                
                # Enhanced IDS Analysis (includes YARA)
                packet_alerts = self.ids_engine.analyze_packet(packet_info, raw_data)
                
                # Store alerts
                for alert in packet_alerts:
                    alerts.append(alert)
                    if len(alerts) > max_alerts:
                        alerts.pop(0)
                    
                    # Emit enhanced alert to web interface
                    socketio.emit('new_alert', alert)
                
                # Store packet
                captured_packets.append(packet_info)
                if len(captured_packets) > max_packets:
                    captured_packets.pop(0)
                
                # Emit packet to web interface
                socketio.emit('new_packet', packet_info)
                
            except Exception as e:
                if self.is_running:
                    socketio.emit('capture_error', {'error': str(e)})
                break
    
    def parse_packet(self, data, packet_num):
        """Parse packet data and return structured information"""
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
        if ip_header['protocol'] == 6:  # TCP
            tcp_info = self.parse_tcp_header(data[ip_header['header_length']:])
            packet_info['src_port'] = tcp_info['src_port']
            packet_info['dst_port'] = tcp_info['dst_port']
            packet_info['flags'] = tcp_info['flags']
        elif ip_header['protocol'] == 17:  # UDP
            udp_info = self.parse_udp_header(data[ip_header['header_length']:])
            packet_info['src_port'] = udp_info['src_port']
            packet_info['dst_port'] = udp_info['dst_port']
        
        # Get payload preview
        payload_start = ip_header['header_length']
        if ip_header['protocol'] in [6, 17]:
            payload_start += 8
        
        if payload_start < len(data):
            payload = data[payload_start:payload_start+32]
            packet_info['payload'] = ' '.join(f'{byte:02x}' for byte in payload)
        
        return packet_info
    
    def parse_ip_header(self, data):
        """Parse IP header from raw packet data"""
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
        """Get protocol name from number"""
        protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP', 89: 'OSPF'
        }
        return protocols.get(protocol_num, f'Unknown({protocol_num})')

# Initialize enhanced packet capture with YARA
packet_capture = PacketCapture()

@app.route('/')
def index():
    """Main page"""
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
    captured_packets = []
    alerts = []
    
    # Start capture
    result = packet_capture.start_capture(interface_ip)
    if result is True:
        is_capturing = True
        capture_thread = threading.Thread(target=packet_capture.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        yara_status = "with YARA support" if YARA_AVAILABLE else "traditional rules only"
        return jsonify({'success': True, 'message': f'Enhanced IDS started {yara_status}'})
    else:
        return jsonify({'success': False, 'message': f'Failed to start capture: {result[1]}'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global is_capturing
    
    if not is_capturing:
        return jsonify({'success': False, 'message': 'No capture running'})
    
    is_capturing = False
    packet_capture.stop_capture()
    return jsonify({'success': True, 'message': 'Enhanced IDS stopped'})

@app.route('/packets')
def get_packets():
    """Get captured packets"""
    return jsonify(captured_packets)

@app.route('/alerts')
def get_alerts():
    """Get IDS alerts"""
    return jsonify(alerts)

@app.route('/rules')
def get_rules():
    """Get IDS rules status"""
    return jsonify(packet_capture.ids_engine.get_rules_status())

@app.route('/yara/stats')
def get_yara_stats():
    """Get YARA engine statistics"""
    return jsonify(packet_capture.ids_engine.get_yara_statistics())

@app.route('/yara/rules')
def get_yara_rules():
    """Get YARA rules details"""
    if packet_capture.ids_engine.yara_engine:
        stats = packet_capture.ids_engine.yara_engine.get_statistics()
        return jsonify(stats['rule_details'])
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

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    yara_status = "with YARA support" if YARA_AVAILABLE else "(YARA not available)"
    emit('connected', {'message': f'Connected to Enhanced IDS server {yara_status}'})
    
    # Send existing data to new client
    for packet in captured_packets[-20:]:
        emit('new_packet', packet)
    for alert in alerts[-10:]:
        emit('new_alert', alert)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass

if __name__ == '__main__':
    print("=" * 60)
    print("ENHANCED INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print("Features:")
    print("• Real-time packet capture")
    print("• Traditional rule-based threat detection")
    if YARA_AVAILABLE:
        print("• YARA pattern matching and malware detection")
        print("• Advanced payload analysis")
    else:
        print("• YARA support: Not available (install yara-python)")
    print("• Alert notifications")
    print("• Web-based monitoring interface")
    print("• Realistic thresholds to prevent false positives")
    print("=" * 60)
    print("Access at: http://localhost:5000")
    print("Remember to run as Administrator!")
    print("=" * 60)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)