#!/usr/bin/env python3
"""
High-Performance Enhanced Intrusion Detection System 
Optimized for 500+ packets/second with working attack detection
FIXED: Corrected false positive detection for DDoS attacks.
ENHANCED: Added Smart Filtering for MS Teams and demonstration mode
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
import queue
from collections import deque, defaultdict
import logging
import ipaddress
from collections import defaultdict
import re



# Add these imports for network topology
from collections import defaultdict
import json
import threading
import time

# Global network topology data structures
network_topology = {
    'nodes': defaultdict(lambda: {
        'packet_count': 0,
        'connections': set(),
        'is_threat': False,
        'first_seen': None,
        'last_seen': None
    }),
    'edges': defaultdict(lambda: {
        'packet_count': 0,
        'first_seen': None,
        'last_seen': None
    }),
    'connection_stats': defaultdict(int),
    'threat_ips': set(),
    'cleanup_interval': 30,
    'max_nodes': 20
}

topology_lock = threading.Lock()

def update_network_topology(packet_info):
    """Update network topology with new packet information"""
    src_ip = packet_info.get('src_ip')
    dst_ip = packet_info.get('dst_ip')
    
    if not src_ip or not dst_ip or src_ip == dst_ip:
        return
    
    current_time = time.time()
    
    with topology_lock:
        # Update source node
        if network_topology['nodes'][src_ip]['first_seen'] is None:
            network_topology['nodes'][src_ip]['first_seen'] = current_time
        
        network_topology['nodes'][src_ip]['packet_count'] += 1
        network_topology['nodes'][src_ip]['last_seen'] = current_time
        network_topology['nodes'][src_ip]['connections'].add(dst_ip)
        
        # Update destination node
        if network_topology['nodes'][dst_ip]['first_seen'] is None:
            network_topology['nodes'][dst_ip]['first_seen'] = current_time
        
        network_topology['nodes'][dst_ip]['packet_count'] += 1
        network_topology['nodes'][dst_ip]['last_seen'] = current_time
        network_topology['nodes'][dst_ip]['connections'].add(src_ip)
        
        # Update edge
        edge_key = f"{src_ip}->{dst_ip}"
        if network_topology['edges'][edge_key]['first_seen'] is None:
            network_topology['edges'][edge_key]['first_seen'] = current_time
        
        network_topology['edges'][edge_key]['packet_count'] += 1
        network_topology['edges'][edge_key]['last_seen'] = current_time
        
        # Update connection stats
        connection_key = tuple(sorted([src_ip, dst_ip]))
        network_topology['connection_stats'][connection_key] += 1

def mark_threat_ip(ip_address):
    """Mark an IP address as a threat"""
    with topology_lock:
        network_topology['threat_ips'].add(ip_address)
        if ip_address in network_topology['nodes']:
            network_topology['nodes'][ip_address]['is_threat'] = True


def get_network_topology_data():
    """Get current network topology data for visualization - FIXED cleanup logic"""
    with topology_lock:
        current_time = time.time()
        cleanup_threshold = current_time - network_topology['cleanup_interval']
        
        # FIX 1: Properly cleanup old nodes BEFORE processing
        nodes_to_remove = []
        for ip, node_data in list(network_topology['nodes'].items()):  # Convert to list to avoid runtime error
            last_seen = node_data.get('last_seen')
            if not last_seen or last_seen < cleanup_threshold:
                nodes_to_remove.append(ip)
        
        # Remove old nodes
        for ip in nodes_to_remove:
            if ip in network_topology['nodes']:
                del network_topology['nodes'][ip]
            network_topology['threat_ips'].discard(ip)
        
        # FIX 2: Cleanup old edges BEFORE processing
        edges_to_remove = []
        for edge_key, edge_data in list(network_topology['edges'].items()):  # Convert to list
            last_seen = edge_data.get('last_seen')
            if not last_seen or last_seen < cleanup_threshold:
                edges_to_remove.append(edge_key)
        
        # Remove old edges
        for edge_key in edges_to_remove:
            if edge_key in network_topology['edges']:
                del network_topology['edges'][edge_key]
        
        # FIX 3: Cleanup old connections
        connections_to_remove = []
        for connection_key in list(network_topology['connection_stats'].keys()):
            # Check if both IPs in the connection still exist
            if len(connection_key) >= 2:
                ip1, ip2 = connection_key[0], connection_key[1]
                if ip1 not in network_topology['nodes'] or ip2 not in network_topology['nodes']:
                    connections_to_remove.append(connection_key)
        
        # Remove old connections
        for connection_key in connections_to_remove:
            if connection_key in network_topology['connection_stats']:
                del network_topology['connection_stats'][connection_key]
        
        # NOW get active nodes (after cleanup)
        active_nodes = []
        for ip, node_data in network_topology['nodes'].items():
            last_seen = node_data.get('last_seen')
            if last_seen and last_seen > cleanup_threshold:  # Should all pass now since we cleaned up
                active_nodes.append({
                    'id': ip,
                    'packet_count': node_data.get('packet_count', 0),
                    'connections': len(node_data.get('connections', set())),
                    'is_threat': ip in network_topology['threat_ips'],
                    'first_seen': node_data.get('first_seen'),
                    'last_seen': last_seen
                })
        
        # Sort and limit
        active_nodes.sort(key=lambda x: x['packet_count'], reverse=True)
        top_nodes = active_nodes[:network_topology['max_nodes']]
        top_node_ips = {node['id'] for node in top_nodes}
        
        # Get active edges (after cleanup)
        active_edges = []
        for edge_key, edge_data in network_topology['edges'].items():
            last_seen = edge_data.get('last_seen')
            if last_seen and last_seen > cleanup_threshold:  # Should all pass now
                try:
                    src_ip, dst_ip = edge_key.split('->', 1)
                    if src_ip in top_node_ips and dst_ip in top_node_ips:
                        active_edges.append({
                            'id': edge_key,
                            'from': src_ip,
                            'to': dst_ip,
                            'packet_count': edge_data.get('packet_count', 0),
                            'first_seen': edge_data.get('first_seen'),
                            'last_seen': last_seen
                        })
                except ValueError:
                    # Skip malformed edge keys
                    continue
        
        # Get top connections (after cleanup)
        top_connections = []
        for connection_key, count in network_topology['connection_stats'].items():
            if len(connection_key) >= 2:
                ip1, ip2 = connection_key[0], connection_key[1]
                if ip1 in top_node_ips or ip2 in top_node_ips:
                    is_threat = ip1 in network_topology['threat_ips'] or ip2 in network_topology['threat_ips']
                    top_connections.append({
                        'ips': f"{ip1} ↔ {ip2}",
                        'count': count,
                        'is_threat': is_threat
                    })
        
        top_connections.sort(key=lambda x: x['count'], reverse=True)
        
        print(f"🧹 Cleanup completed: Removed {len(nodes_to_remove)} nodes, {len(edges_to_remove)} edges, {len(connections_to_remove)} connections")
        
        return {
            'nodes': top_nodes,
            'edges': active_edges,
            'top_connections': top_connections[:10],
            'stats': {
                'total_nodes': len(network_topology['nodes']),
                'total_edges': len(network_topology['edges']),
                'threat_count': len(network_topology['threat_ips']),
                'active_nodes': len(active_nodes),
                'cleanup_removed': {
                    'nodes': len(nodes_to_remove),
                    'edges': len(edges_to_remove),
                    'connections': len(connections_to_remove)
                }
            }
        }


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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# OPTIMIZED CONFIG FOR HIGH PERFORMANCE
CONFIG = {
    'max_packets': 1000,       # Increased buffer
    'max_alerts': 200,         # More alerts
    'environment': 'testing',  # Testing mode - more sensitive
    'debug_mode': False,
    'batch_size': 50,          # Larger batches for performance
    'update_interval': 0.1,    # Faster updates (10x per second)
    'max_memory_mb': 200,
    'cleanup_interval': 60     # Less frequent cleanup
}

# SMART FILTER CONFIG FOR MS TEAMS AND DEMONSTRATION MODE
SMART_FILTER_CONFIG = {
    'enable_smart_filtering': True,
    'bypass_applications': {
        # MS Teams and communication apps
        'teams_ports': [443, 80, 3478, 3479, 3480, 3481],  # Teams uses these
        'teams_domains': ['teams.microsoft.com', 'teams.live.com', 'api.teams.skype.com'],
        'zoom_ports': [443, 80, 8801, 8802],
        'webex_ports': [443, 80, 9943],
        
        # Common legitimate ports to reduce noise
        'legitimate_ports': [53, 80, 443, 25, 465, 587, 993, 995, 123],  # DNS, HTTP, HTTPS, Email, NTP
        
        # High-volume protocols to limit
        'limit_protocols': ['DNS', 'NTP', 'DHCP'],
        
        # Rate limiting for legitimate traffic
        'max_packets_per_second': 50,  # Per application
    },
    'test_mode': {
        'enable_test_prioritization': True,
        'test_ports': [22, 21, 23, 1433, 3389, 5900],  # Prioritize attack testing ports
        'test_ips': ['8.8.8.8', '1.1.1.1', '127.0.0.2'],  # Your test target IPs
    }
}

# Global variables with thread-safe collections
capture_thread = None
is_capturing = False
captured_packets = deque(maxlen=CONFIG['max_packets'])
alerts = deque(maxlen=CONFIG['max_alerts'])
packet_stats = defaultdict(int)

# High-performance queues
packet_queue = queue.Queue(maxsize=2000)  # Larger queue
alert_queue = queue.Queue(maxsize=1000)   # Larger alert queue

# Rate limiting - reduced for testing
last_ui_update = 0
update_lock = threading.Lock()

# =============================================================================
# SMART PACKET FILTER CLASS
# =============================================================================

class SmartPacketFilter:
    """Intelligent packet filtering to reduce noise during demonstrations"""
    
    def __init__(self):
        self.legitimate_traffic_count = defaultdict(int)
        self.last_reset_time = time.time()
        self.blocked_packet_count = 0
        self.allowed_packet_count = 0
        
        # Known legitimate application patterns
        self.legitimate_patterns = {
            'teams': [
                b'teams.microsoft.com',
                b'api.teams.skype.com', 
                b'teams.live.com',
                b'stun.l.google.com'
            ],
            'browsers': [
                b'googleapis.com',
                b'gstatic.com',
                b'google-analytics.com',
                b'doubleclick.net'
            ],
            'windows_updates': [
                b'windowsupdate.microsoft.com',
                b'update.microsoft.com',
                b'download.microsoft.com'
            ]
        }
    
    def should_process_packet(self, packet_info, raw_data=None):
        """Determine if packet should be processed by IDS"""
        
        if not SMART_FILTER_CONFIG['enable_smart_filtering']:
            return True
        
        # Always process test traffic
        if self._is_test_traffic(packet_info):
            self.allowed_packet_count += 1
            return True
        
        # Check if it's legitimate application traffic
        if self._is_legitimate_app_traffic(packet_info, raw_data):
            self.blocked_packet_count += 1
            return False
        
        # Rate limit high-volume legitimate protocols
        if self._should_rate_limit(packet_info):
            self.blocked_packet_count += 1
            return False
        
        # Process everything else
        self.allowed_packet_count += 1
        return True
    
    def _is_test_traffic(self, packet_info):
        """Check if this is test/attack traffic we want to prioritize"""
        test_config = SMART_FILTER_CONFIG['test_mode']
        
        if not test_config['enable_test_prioritization']:
            return False
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        
        # Prioritize traffic to/from test IPs
        if src_ip in test_config['test_ips'] or dst_ip in test_config['test_ips']:
            return True
        
        # Prioritize traffic to test ports (attack simulation)
        if dst_port in test_config['test_ports']:
            return True
        
        # Prioritize external IP ranges (likely test traffic)
        if self._is_external_ip(src_ip) or self._is_external_ip(dst_ip):
            return True
        
        return False
    
    def _is_legitimate_app_traffic(self, packet_info, raw_data):
        """Check if this is legitimate application traffic to filter out"""
        dst_port = packet_info.get('dst_port')
        src_port = packet_info.get('src_port')
        protocol = packet_info.get('protocol')
        
        bypass_config = SMART_FILTER_CONFIG['bypass_applications']
        
        # Filter MS Teams traffic
        if dst_port in bypass_config['teams_ports'] or src_port in bypass_config['teams_ports']:
            if raw_data and any(domain in raw_data for domain in [b'teams.microsoft.com', b'skype.com']):
                return True
        
        # Filter other communication apps
        if (dst_port in bypass_config['zoom_ports'] or 
            dst_port in bypass_config['webex_ports']):
            return True
        
        # Filter high-volume legitimate protocols
        if protocol in bypass_config['limit_protocols']:
            return True
        
        # Check payload for legitimate app patterns
        if raw_data:
            for app, patterns in self.legitimate_patterns.items():
                if any(pattern in raw_data for pattern in patterns):
                    return True
        
        return False
    
    def _should_rate_limit(self, packet_info):
        """Apply rate limiting to reduce packet volume"""
        current_time = time.time()
        
        # Reset counters every second
        if current_time - self.last_reset_time >= 1.0:
            self.legitimate_traffic_count.clear()
            self.last_reset_time = current_time
        
        # Rate limit by destination port
        dst_port = packet_info.get('dst_port')
        if dst_port in SMART_FILTER_CONFIG['bypass_applications']['legitimate_ports']:
            self.legitimate_traffic_count[dst_port] += 1
            
            max_pps = SMART_FILTER_CONFIG['bypass_applications']['max_packets_per_second']
            if self.legitimate_traffic_count[dst_port] > max_pps:
                return True
        
        return False
    
    def _is_external_ip(self, ip_str):
        """Check if IP is external (likely test traffic)"""
        if not ip_str or ip_str in ['unknown', '127.0.0.1']:
            return False
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Consider these as "external" for testing purposes
            external_ranges = [
                ipaddress.ip_network('8.8.8.0/24'),    # Google DNS
                ipaddress.ip_network('1.1.1.0/24'),    # Cloudflare DNS
                ipaddress.ip_network('208.67.222.0/24') # OpenDNS
            ]
            
            for network in external_ranges:
                if ip in network:
                    return True
            
            # Also consider public IPs as external
            return not ip.is_private
            
        except ValueError:
            return False
    
    def get_filter_stats(self):
        """Get filtering statistics"""
        total = self.allowed_packet_count + self.blocked_packet_count
        blocked_percentage = (self.blocked_packet_count / total * 100) if total > 0 else 0
        
        return {
            'total_packets': total,
            'allowed_packets': self.allowed_packet_count,
            'blocked_packets': self.blocked_packet_count,
            'blocked_percentage': round(blocked_percentage, 1),
            'legitimate_traffic_counts': dict(self.legitimate_traffic_count)
        }


# Enhanced IDS Configuration
# Enhanced IDS Configuration
ENHANCED_CONFIG = {
    'max_packets': 1000,
    'max_alerts': 200,
    'environment': 'production',  # Changed to production for better filtering
    'debug_mode': False,
    'batch_size': 50,
    'update_interval': 0.1,
    'max_memory_mb': 200,
    'cleanup_interval': 60
}

# Advanced Smart Filter Configuration
ADVANCED_SMART_FILTER_CONFIG = {
    'enable_smart_filtering': True,
    'ddos_prevention': {
        # DDoS-specific filtering
        'enable_ddos_filtering': True,
        'volume_thresholds': {
            'web_traffic_pps': 200,      # Packets per second for web traffic
            'dns_traffic_pps': 50,       # Packets per second for DNS
            'general_traffic_pps': 100,  # General traffic limit
        },
        'burst_detection': {
            'enable': True,
            'spike_threshold': 3.0,      # 3x normal traffic = potential attack
            'min_baseline': 20,          # Minimum packets for baseline calculation
        },
        'whitelist_applications': [
            'teams.microsoft.com',
            'zoom.us', 
            'webex.com',
            'meet.google.com',
            'discord.com'
        ]
    },
    'bypass_applications': {
        # Communication apps (expanded list)
        'teams_ports': [443, 80, 3478, 3479, 3480, 3481, 50051, 50052],
        'zoom_ports': [443, 80, 8801, 8802, 8803],
        'webex_ports': [443, 80, 9943, 5004],
        'discord_ports': [443, 80, 50001, 50002],
        
        # System and development traffic
        'development_ports': [3000, 3001, 8000, 8080, 8443, 5000, 5173],
        'system_ports': [53, 123, 67, 68, 22, 25, 465, 587, 993, 995],
        
        # Rate limiting for legitimate traffic
        'max_packets_per_second': {
            'web_browsing': 100,
            'video_conference': 200,
            'system_services': 50,
            'development': 150
        }
    },
    'false_positive_reduction': {
        'enable': True,
        'learning_period': 300,  # 5 minutes to learn normal patterns
        'baseline_adjustment': True,
        'context_awareness': True,
        'user_behavior_analysis': True
    }
}

class SmartDDoSFilter:
    """
    Smart DDoS filtering to prevent false positives
    Works alongside the enhanced DDoS detection rule
    """
    
    def __init__(self):
        self.traffic_baselines = defaultdict(lambda: {
            'normal_rate': 0,
            'measurements': deque(maxlen=20),
            'last_update': time.time(),
            'application_type': 'unknown'
        })
        
        self.learning_mode = True
        self.learning_start_time = time.time()
        
        # Application signatures for identification
        self.app_signatures = {
            'teams': {
                'domains': [b'teams.microsoft.com', b'stun.l.google.com'],
                'ports': [443, 3478, 3479, 3480, 3481],
                'typical_rate': (10, 150)  # Normal packet rate range
            },
            'zoom': {
                'domains': [b'zoom.us', b'zmcdn.net'],
                'ports': [443, 8801, 8802],
                'typical_rate': (15, 200)
            },
            'browsing': {
                'domains': [b'googleapis.com', b'gstatic.com'],
                'ports': [443, 80],
                'typical_rate': (5, 50)
            }
        }
    
    def should_trigger_ddos_alert(self, src_ip, dst_ip, dst_port, packet_rate, raw_data=None):
        """
        Determine if traffic pattern should trigger DDoS alert
        Returns: (should_alert: bool, reason: str)
        """
        
        # Check if we're still in learning mode
        if self.learning_mode and time.time() - self.learning_start_time < ADVANCED_SMART_FILTER_CONFIG['false_positive_reduction']['learning_period']:
            self._update_baseline(src_ip, dst_ip, dst_port, packet_rate, raw_data)
            return False, "Learning mode - building traffic baselines"
        
        # Disable learning mode after learning period
        if self.learning_mode:
            self.learning_mode = False
            print("📚 Learning mode completed - DDoS detection now active")
        
        # Identify application type
        app_type = self._identify_application(dst_ip, dst_port, raw_data)
        
        # Get baseline for this traffic pattern
        connection_key = f"{src_ip}->{dst_ip}:{dst_port}"
        baseline = self.traffic_baselines[connection_key]
        baseline['application_type'] = app_type
        
        # Check against application-specific thresholds
        threshold = self._get_threshold_for_app(app_type, dst_port)
        
        if packet_rate < threshold:
            return False, f"Below threshold for {app_type} traffic ({packet_rate} < {threshold})"
        
        # Check against learned baseline
        if baseline['normal_rate'] > 0:
            spike_ratio = packet_rate / baseline['normal_rate']
            if spike_ratio < ADVANCED_SMART_FILTER_CONFIG['ddos_prevention']['burst_detection']['spike_threshold']:
                return False, f"Within normal range - {spike_ratio:.1f}x baseline"
        
        # Additional context checks
        if self._is_likely_legitimate(src_ip, dst_ip, dst_port, app_type):
            return False, f"Legitimate {app_type} traffic pattern detected"
        
        # If we reach here, likely a real attack
        return True, f"DDoS attack detected: {packet_rate} pps to {app_type} service (threshold: {threshold})"
    
    def _identify_application(self, dst_ip, dst_port, raw_data):
        """Identify what application this traffic belongs to"""
        
        # Check by port first
        config = ADVANCED_SMART_FILTER_CONFIG['bypass_applications']
        
        if dst_port in config['teams_ports']:
            if raw_data and any(sig in raw_data for sig in self.app_signatures['teams']['domains']):
                return 'teams'
            return 'conference'
        
        if dst_port in config['zoom_ports']:
            return 'zoom'
        
        if dst_port in config['webex_ports']:
            return 'webex'
        
        if dst_port in config['development_ports']:
            return 'development'
        
        if dst_port in config['system_ports']:
            return 'system'
        
        if dst_port in [80, 443]:
            return 'web'
        
        return 'unknown'
    
    def _get_threshold_for_app(self, app_type, dst_port):
        """Get appropriate threshold based on application type"""
        
        config = ADVANCED_SMART_FILTER_CONFIG['ddos_prevention']['volume_thresholds']
        
        thresholds = {
            'teams': 200,
            'zoom': 150, 
            'webex': 150,
            'conference': 150,
            'web': config['web_traffic_pps'],
            'development': 100,
            'system': 75,
            'unknown': config['general_traffic_pps']
        }
        
        return thresholds.get(app_type, config['general_traffic_pps'])
    
    def _is_likely_legitimate(self, src_ip, dst_ip, dst_port, app_type):
        """Check if traffic pattern appears legitimate"""
        
        # Internal to internal communication
        try:
            src_addr = ipaddress.ip_address(src_ip)
            dst_addr = ipaddress.ip_address(dst_ip)
            
            if src_addr.is_private and dst_addr.is_private:
                return True  # Internal traffic is usually legitimate
        except ValueError:
            pass
        
        # Known application traffic
        if app_type in ['teams', 'zoom', 'webex', 'conference']:
            return True
        
        # Web browsing to external sites
        if app_type == 'web' and dst_port in [80, 443]:
            try:
                dst_addr = ipaddress.ip_address(dst_ip)
                if not dst_addr.is_private:  # External web traffic
                    return True
            except ValueError:
                pass
        
        return False
    
    def _update_baseline(self, src_ip, dst_ip, dst_port, packet_rate, raw_data):
        """Update traffic baseline during learning period"""
        
        connection_key = f"{src_ip}->{dst_ip}:{dst_port}"
        baseline = self.traffic_baselines[connection_key]
        
        # Add measurement
        baseline['measurements'].append(packet_rate)
        baseline['last_update'] = time.time()
        
        # Calculate new baseline
        if len(baseline['measurements']) >= 5:
            measurements = list(baseline['measurements'])
            # Use median to avoid outliers
            measurements.sort()
            baseline['normal_rate'] = measurements[len(measurements) // 2]

# Integration with existing IDS engine
class EnhancedIDSEngine:
    """Enhanced IDS engine with smart DDoS filtering"""
    
    def __init__(self):
        self.traditional_rules = [
            HighPerformancePortScanRule(),
            EnhancedDDoSDetectionRule(),  # Use the new enhanced rule
            HighPerformanceBruteForceRule(),
            HighPerformanceDNSTunnelingRule(),
            HighPerformanceReconRule(),
            SuspiciousPayloadRule(),
        ]
        
        # Add smart filtering
        self.ddos_filter = SmartDDoSFilter()
        self.total_alerts = 0
        
    def analyze_packet(self, packet_info, raw_data=None):
        """Enhanced packet analysis with smart filtering"""
        
        triggered_alerts = []
        
        for rule in self.traditional_rules:
            if not rule.enabled:
                continue
            
            # Special handling for DDoS rule
            if isinstance(rule, EnhancedDDoSDetectionRule):
                if rule.check(packet_info, raw_data):
                    # Additional validation through smart filter
                    src_ip = packet_info.get('src_ip')
                    dst_ip = packet_info.get('dst_ip')
                    dst_port = packet_info.get('dst_port')
                    
                    # Calculate current packet rate (simplified)
                    packet_rate = 100  # This should be calculated from actual traffic
                    
                    should_alert, reason = self.ddos_filter.should_trigger_ddos_alert(
                        src_ip, dst_ip, dst_port, packet_rate, raw_data
                    )
                    
                    if should_alert and rule.trigger():
                        alert = self._create_alert(rule, packet_info)
                        alert['additional_info'] = reason
                        triggered_alerts.append(alert)
                        print(f"🚨 CONFIRMED DDoS ALERT: {reason}")
                    elif not should_alert:
                        print(f"🛡️ DDoS alert suppressed: {reason}")
            else:
                # Normal rule processing
                if rule.check(packet_info, raw_data):
                    if rule.trigger():
                        alert = self._create_alert(rule, packet_info)
                        triggered_alerts.append(alert)
        
        self.total_alerts += len(triggered_alerts)
        return triggered_alerts
    
    def _create_alert(self, rule, packet_info):
        """Create standardized alert"""
        return {
            'id': self.total_alerts + 1,
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'rule_name': rule.name,
            'description': rule.description,
            'severity': rule.severity,
            'detection_type': 'Enhanced',
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('protocol'),
            'packet_size': packet_info.get('size'),
            'packet_id': packet_info.get('id')
        }



# =============================================================================
# HIGH-PERFORMANCE BASE CLASSES
# =============================================================================

class IDSRule:
    """Base class for all IDS detection rules - high performance"""
    def __init__(self, name, description, severity="Medium"):
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = True
        self.trigger_count = 0
        self.last_triggered = None
        # REDUCED rate limiting for testing
        self.rate_limit = 20  # More triggers allowed per minute
        self.trigger_times = deque(maxlen=30)
    
    def check(self, packet_info, raw_data=None):
        """Override this method in rule implementations"""
        return False
    
    def trigger(self):
        """Mark rule as triggered with minimal rate limiting"""
        current_time = time.time()
        
        # Relaxed rate limiting for testing
        recent_triggers = [t for t in self.trigger_times if current_time - t < 60]
        if len(recent_triggers) >= self.rate_limit:
            # Allow occasional bypass for testing
            if self.trigger_count % 10 == 0:
                pass  # Allow every 10th trigger even if rate limited
            else:
                return False
        
        self.trigger_count += 1
        self.last_triggered = datetime.now()
        self.trigger_times.append(current_time)
        return True

# =============================================================================
# ATTACK-DETECTION OPTIMIZED RULES
# =============================================================================

class HighPerformancePortScanRule(IDSRule):
    """Port scan detection optimized for testing"""
    def __init__(self):
        super().__init__(
            name="Port Scan Detected",
            description="Multiple connection attempts to different ports",
            severity="High"
        )
        self.port_attempts = defaultdict(list)
        self.time_window = 60
        self.threshold = 15  # REDUCED for easier testing
        self.cleanup_interval = 30
        self.last_cleanup = time.time()
        
        # MINIMAL legitimate ports for testing
        self.legitimate_ports = frozenset({80, 443})  # Only web ports
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'TCP':
            return False
        
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        current_time = time.time()
        
        # Skip only essential legitimate ports
        if dst_port in self.legitimate_ports:
            return False
        
        # REMOVED private IP filtering for testing
        
        if src_ip and dst_port:
            # Periodic cleanup
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_entries(current_time)
                self.last_cleanup = current_time
            
            attempts = self.port_attempts[src_ip]
            attempts.append({'port': dst_port, 'time': current_time})
            
            # Keep only recent attempts
            recent_attempts = [a for a in attempts if current_time - a['time'] <= self.time_window]
            self.port_attempts[src_ip] = recent_attempts
            
            # Check threshold
            unique_ports = set(attempt['port'] for attempt in recent_attempts)
            return len(unique_ports) >= self.threshold
        
        return False
    
    def _cleanup_old_entries(self, current_time):
        """Clean up old entries"""
        to_remove = []
        for src_ip, attempts in self.port_attempts.items():
            recent = [a for a in attempts if current_time - a['time'] <= self.time_window]
            if recent:
                self.port_attempts[src_ip] = recent
            else:
                to_remove.append(src_ip)
        
        for ip in to_remove:
            del self.port_attempts[ip]




class EnhancedDDoSDetectionRule(IDSRule):
    """
    Enhanced DDoS detection with false positive reduction
    Focuses on actual attack patterns rather than just volume
    """
    def __init__(self):
        super().__init__(
            name="DDoS Attack Detected",
            description="Sophisticated DDoS attack pattern detected",
            severity="High"
        )
        # Track packets per source-destination-port combination for specificity
        self.connection_patterns = defaultdict(lambda: defaultdict(lambda: defaultdict(deque)))
        self.time_window = 60  # Longer window for better analysis
        
        # Different thresholds for different traffic types
        self.thresholds = {
            'web_traffic': 500,      # Higher threshold for web traffic (ports 80, 443)
            'dns_traffic': 200,      # Moderate threshold for DNS (port 53)
            'general_traffic': 150,  # Lower threshold for other traffic
            'suspicious_ports': 100  # Lower threshold for unusual ports
        }
        
        self.cleanup_interval = 30
        self.last_cleanup = time.time()
        
        # Common legitimate traffic patterns to whitelist
        self.legitimate_patterns = {
            # Web browsing patterns
            'web_ports': {80, 443, 8080, 8443},
            # DNS and system services
            'system_ports': {53, 123, 67, 68},
            # Video conferencing (MS Teams, Zoom, etc.)
            'conference_ports': {3478, 3479, 3480, 3481, 8801, 8802, 9943},
            # Common application ports
            'app_ports': {25, 465, 587, 993, 995, 110, 143}
        }
        
        # Track burst patterns (sudden spikes indicate attacks)
        self.burst_detection = defaultdict(lambda: {
            'recent_counts': deque(maxlen=10),  # Last 10 measurements
            'baseline': 0,
            'last_update': time.time()
        })
    
    def check(self, packet_info, raw_data=None):
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        current_time = time.time()
        
        # Skip analysis for obviously legitimate patterns
        if self._is_legitimate_traffic(src_ip, dst_ip, dst_port, protocol):
            return False
        
        # Skip localhost and internal communication
        if src_ip == '127.0.0.1' or src_ip == dst_ip:
            return False
        
        # Skip private-to-private communication (likely legitimate)
        if self._both_private_ips(src_ip, dst_ip):
            return False
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Create unique connection identifier
        connection_key = f"{src_ip}->{dst_ip}:{dst_port}"
        
        # Track packets for this specific connection
        timestamps = self.connection_patterns[src_ip][dst_ip][dst_port]
        timestamps.append(current_time)
        
        # Keep only recent timestamps
        cutoff_time = current_time - self.time_window
        while timestamps and timestamps[0] < cutoff_time:
            timestamps.popleft()
        
        packet_count = len(timestamps)
        
        # Determine appropriate threshold based on traffic type
        threshold = self._get_threshold_for_traffic(dst_port, protocol)
        
        # Check for basic volume threshold
        if packet_count < threshold:
            return False
        
        # Additional validation: check for burst patterns
        if not self._detect_burst_pattern(connection_key, packet_count, current_time):
            return False
        
        # Additional validation: check packet rate consistency (attacks are often consistent)
        if not self._check_attack_consistency(timestamps):
            return False
        
        # If we reach here, it's likely a real attack
        print(f"🚨 DDoS Attack Confirmed: {src_ip} → {dst_ip}:{dst_port}")
        print(f"   • Packet count: {packet_count} in {self.time_window}s")
        print(f"   • Threshold: {threshold}")
        print(f"   • Pattern: Burst detected with consistent rate")
        
        return True
    
    def _is_legitimate_traffic(self, src_ip, dst_ip, dst_port, protocol):
        """Check if traffic pattern appears legitimate"""
        
        # Web traffic to common web servers (likely browsing)
        if dst_port in self.legitimate_patterns['web_ports']:
            # Allow higher volume for web traffic
            return False  # Don't skip, but use higher threshold
        
        # System services (DNS, NTP, DHCP)
        if dst_port in self.legitimate_patterns['system_ports']:
            return False  # Don't skip, but use higher threshold
        
        # Video conferencing traffic
        if dst_port in self.legitimate_patterns['conference_ports']:
            return True  # Skip - likely MS Teams or similar
        
        # Email and other application traffic
        if dst_port in self.legitimate_patterns['app_ports']:
            return False  # Don't skip, but use higher threshold
        
        return False
    
    def _both_private_ips(self, src_ip, dst_ip):
        """Check if both IPs are private (internal network communication)"""
        try:
            src_addr = ipaddress.ip_address(src_ip)
            dst_addr = ipaddress.ip_address(dst_ip)
            return src_addr.is_private and dst_addr.is_private
        except ValueError:
            return False
    
    def _get_threshold_for_traffic(self, dst_port, protocol):
        """Get appropriate threshold based on traffic type"""
        
        # Web traffic gets higher threshold
        if dst_port in self.legitimate_patterns['web_ports']:
            return self.thresholds['web_traffic']
        
        # DNS traffic
        if dst_port == 53:
            return self.thresholds['dns_traffic']
        
        # System services
        if dst_port in self.legitimate_patterns['system_ports']:
            return self.thresholds['general_traffic']
        
        # Unusual/suspicious ports get lower threshold
        if dst_port > 10000 or dst_port in {1234, 31337, 12345, 54321}:
            return self.thresholds['suspicious_ports']
        
        return self.thresholds['general_traffic']
    
    def _detect_burst_pattern(self, connection_key, current_count, current_time):
        """Detect sudden burst in traffic (characteristic of DDoS attacks)"""
        
        burst_data = self.burst_detection[connection_key]
        
        # Update burst detection data every 5 seconds
        if current_time - burst_data['last_update'] >= 5.0:
            burst_data['recent_counts'].append(current_count)
            burst_data['last_update'] = current_time
            
            # Calculate baseline (average of previous measurements)
            if len(burst_data['recent_counts']) >= 3:
                recent_counts = list(burst_data['recent_counts'])
                burst_data['baseline'] = sum(recent_counts[:-1]) / len(recent_counts[:-1])
                
                # Check for sudden spike (burst)
                current_rate = recent_counts[-1]
                if burst_data['baseline'] > 0:
                    spike_ratio = current_rate / burst_data['baseline']
                    
                    # Require at least 3x spike for DDoS detection
                    if spike_ratio >= 3.0 and current_rate >= 100:
                        print(f"💥 Burst pattern detected for {connection_key}: {spike_ratio:.1f}x spike")
                        return True
        
        return False
    
    def _check_attack_consistency(self, timestamps):
        """Check if packet timing is consistent with an attack pattern"""
        if len(timestamps) < 20:  # Need sufficient data
            return True  # Allow if not enough data
        
        # Convert to list for analysis
        times = list(timestamps)
        intervals = []
        
        # Calculate intervals between packets
        for i in range(1, len(times)):
            intervals.append(times[i] - times[i-1])
        
        if not intervals:
            return True
        
        # Calculate consistency metrics
        avg_interval = sum(intervals) / len(intervals)
        
        # Check for very consistent timing (bot-like behavior)
        consistent_count = 0
        for interval in intervals:
            if abs(interval - avg_interval) < 0.1:  # Very consistent timing
                consistent_count += 1
        
        consistency_ratio = consistent_count / len(intervals)
        
        # High consistency (>70%) suggests automated attack
        if consistency_ratio > 0.7 and avg_interval < 1.0:  # Consistent + fast
            print(f"🤖 Bot-like consistency detected: {consistency_ratio:.1f} consistency ratio")
            return True
        
        # Check for very rapid sustained rate (another attack indicator)
        rapid_intervals = [i for i in intervals if i < 0.01]  # < 10ms apart
        if len(rapid_intervals) > len(intervals) * 0.5:  # >50% rapid intervals
            print(f"⚡ Rapid sustained rate detected: {len(rapid_intervals)}/{len(intervals)} rapid intervals")
            return True
        
        return False  # Doesn't match attack patterns
    
    def _cleanup_old_entries(self, current_time):
        """Enhanced cleanup for nested data structure"""
        cutoff_time = current_time - self.time_window
        
        # Clean up connection patterns
        src_ips_to_remove = []
        for src_ip, dst_map in self.connection_patterns.items():
            dst_ips_to_remove = []
            for dst_ip, port_map in dst_map.items():
                ports_to_remove = []
                for port, timestamps in port_map.items():
                    # Remove old timestamps
                    while timestamps and timestamps[0] < cutoff_time:
                        timestamps.popleft()
                    
                    # Remove empty port entries
                    if not timestamps:
                        ports_to_remove.append(port)
                
                # Remove empty ports
                for port in ports_to_remove:
                    del port_map[port]
                
                # Mark empty destinations for removal
                if not port_map:
                    dst_ips_to_remove.append(dst_ip)
            
            # Remove empty destinations
            for dst_ip in dst_ips_to_remove:
                del dst_map[dst_ip]
            
            # Mark empty sources for removal
            if not dst_map:
                src_ips_to_remove.append(src_ip)
        
        # Remove empty sources
        for src_ip in src_ips_to_remove:
            del self.connection_patterns[src_ip]
        
        # Clean up burst detection data
        burst_keys_to_remove = []
        for key, data in self.burst_detection.items():
            if current_time - data['last_update'] > self.time_window * 2:
                burst_keys_to_remove.append(key)
        
        for key in burst_keys_to_remove:
            del self.burst_detection[key]

# Additional helper class for DDoS analysis
class DDoSAnalyzer:
    """
    Advanced DDoS analysis helper
    Provides additional metrics and validation
    """
    
    @staticmethod
    def analyze_traffic_pattern(packet_info_list):
        """Analyze a list of packets for DDoS characteristics"""
        if not packet_info_list:
            return {"is_ddos": False, "confidence": 0, "reason": "No data"}
        
        # Group by source IP
        sources = defaultdict(list)
        for packet in packet_info_list:
            sources[packet.get('src_ip', 'unknown')].append(packet)
        
        # Look for suspicious patterns
        suspicious_indicators = 0
        total_indicators = 0
        
        for src_ip, packets in sources.items():
            if len(packets) < 10:  # Skip low-volume sources
                continue
            
            total_indicators += 4  # Total possible indicators per source
            
            # Indicator 1: High packet rate
            if len(packets) > 100:
                suspicious_indicators += 1
            
            # Indicator 2: Targeting single destination
            destinations = set(p.get('dst_ip') for p in packets)
            if len(destinations) == 1:
                suspicious_indicators += 1
            
            # Indicator 3: Consistent timing
            timestamps = [p.get('timestamp') for p in packets if p.get('timestamp')]
            if DDoSAnalyzer._has_consistent_timing(timestamps):
                suspicious_indicators += 1
            
            # Indicator 4: Unusual source IP patterns
            if DDoSAnalyzer._is_suspicious_source(src_ip):
                suspicious_indicators += 1
        
        confidence = (suspicious_indicators / total_indicators) if total_indicators > 0 else 0
        
        return {
            "is_ddos": confidence > 0.6,
            "confidence": round(confidence * 100, 1),
            "suspicious_indicators": suspicious_indicators,
            "total_indicators": total_indicators,
            "reason": f"Confidence: {confidence:.1%} based on traffic analysis"
        }
    
    @staticmethod
    def _has_consistent_timing(timestamps):
        """Check if timestamps show consistent (bot-like) timing"""
        if len(timestamps) < 5:
            return False
        
        try:
            # Convert timestamps to seconds if needed
            times = []
            for ts in timestamps:
                if isinstance(ts, str):
                    # Parse timestamp format like "14:30:45.123"
                    continue  # Skip string timestamps for now
                times.append(float(ts))
            
            if len(times) < 5:
                return False
            
            # Calculate intervals
            intervals = [times[i] - times[i-1] for i in range(1, len(times))]
            
            if not intervals:
                return False
            
            # Check for consistency
            avg_interval = sum(intervals) / len(intervals)
            consistent_count = sum(1 for interval in intervals 
                                 if abs(interval - avg_interval) < avg_interval * 0.1)
            
            return consistent_count / len(intervals) > 0.8
        
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def _is_suspicious_source(src_ip):
        """Check if source IP appears suspicious"""
        if not src_ip or src_ip == 'unknown':
            return True
        
        try:
            ip_addr = ipaddress.ip_address(src_ip)
            
            # Check for suspicious IP ranges
            suspicious_ranges = [
                ipaddress.ip_network('0.0.0.0/8'),      # Invalid range
                ipaddress.ip_network('169.254.0.0/16'), # Link-local
                ipaddress.ip_network('224.0.0.0/4'),    # Multicast
            ]
            
            for network in suspicious_ranges:
                if ip_addr in network:
                    return True
            
            return False
        
        except ValueError:
            return True  # Invalid IP format is suspicious





class HighPerformanceBruteForceRule(IDSRule):
    """Brute force detection optimized for testing"""
    def __init__(self):
        super().__init__(
            name="Brute Force Attack Detected",
            description="Multiple authentication attempts detected",
            severity="High"
        )
        self.connection_attempts = defaultdict(deque)
        self.time_window = 300
        self.threshold = 30  # REDUCED threshold for testing
        self.auth_ports = frozenset({22, 23, 21, 3389, 5900, 1433, 3306, 5432})
        self.cleanup_interval = 60
        self.last_cleanup = time.time()
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'TCP':
            return False
        
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Only check auth ports, but don't skip any IPs except actual localhost
        if dst_port not in self.auth_ports or not src_ip or src_ip == '127.0.0.1':
            return False
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        key = f"{src_ip}:{dst_port}"
        timestamps = self.connection_attempts[key]
        timestamps.append(current_time)
        
        # Keep only recent attempts
        while timestamps and current_time - timestamps[0] > self.time_window:
            timestamps.popleft()
        
        attempt_count = len(timestamps)
        if attempt_count >= self.threshold:
            print(f"🚨 Brute Force detected: {src_ip}:{dst_port} made {attempt_count} attempts")
            return True
        
        return False
    
    def _cleanup_old_entries(self, current_time):
        to_remove = []
        for key, timestamps in self.connection_attempts.items():
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()
            if not timestamps:
                to_remove.append(key)
        
        for key in to_remove:
            del self.connection_attempts[key]

class HighPerformanceDNSTunnelingRule(IDSRule):
    """DNS tunneling detection optimized for testing"""
    def __init__(self):
        super().__init__(
            name="DNS Tunneling Detected",
            description="Suspicious DNS query patterns detected",
            severity="High"
        )
        self.dns_queries = defaultdict(deque)
        self.time_window = 60
        self.threshold = 50  # REDUCED threshold for testing
        self.cleanup_interval = 30
        self.last_cleanup = time.time()
    
    def check(self, packet_info, raw_data=None):
        if not (packet_info.get('protocol') == 'UDP' and packet_info.get('dst_port') == 53):
            return False
        
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Only skip actual localhost
        if src_ip == '127.0.0.1':
            return False
        
        if src_ip:
            # Periodic cleanup
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_entries(current_time)
                self.last_cleanup = current_time
            
            timestamps = self.dns_queries[src_ip]
            timestamps.append(current_time)
            
            # Keep only recent queries
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()
            
            query_count = len(timestamps)
            if query_count >= self.threshold:
                print(f"🚨 DNS Tunneling detected: {src_ip} made {query_count} DNS queries")
                return True
        
        return False
    
    def _cleanup_old_entries(self, current_time):
        to_remove = []
        for src_ip, timestamps in self.dns_queries.items():
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()
            if not timestamps:
                to_remove.append(src_ip)
        
        for ip in to_remove:
            del self.dns_queries[ip]

class HighPerformanceReconRule(IDSRule):
    """Network reconnaissance detection"""
    def __init__(self):
        super().__init__(
            name="Network Reconnaissance Detected",
            description="ICMP reconnaissance activity detected",
            severity="Medium"
        )
        self.icmp_requests = defaultdict(deque)
        self.time_window = 60
        self.threshold = 25  # REDUCED threshold
        self.cleanup_interval = 30
        self.last_cleanup = time.time()
    
    def check(self, packet_info, raw_data=None):
        if packet_info.get('protocol') != 'ICMP':
            return False
        
        src_ip = packet_info.get('src_ip')
        current_time = time.time()
        
        # Only skip actual localhost
        if src_ip == '127.0.0.1':
            return False
        
        if src_ip:
            # Periodic cleanup
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_entries(current_time)
                self.last_cleanup = current_time
            
            timestamps = self.icmp_requests[src_ip]
            timestamps.append(current_time)
            
            # Keep only recent requests
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()
            
            icmp_count = len(timestamps)
            if icmp_count >= self.threshold:
                print(f"🚨 Network Recon detected: {src_ip} sent {icmp_count} ICMP packets")
                return True
        
        return False
    
    def _cleanup_old_entries(self, current_time):
        to_remove = []
        for src_ip, timestamps in self.icmp_requests.items():
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()
            if not timestamps:
                to_remove.append(src_ip)
        
        for ip in to_remove:
            del self.icmp_requests[ip]

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
        
        # Check reasonable payload sizes
        if len(payload) > 10000:
            return False
        
        detected = any(pattern in payload for pattern in self.malicious_patterns)
        if detected:
            print(f"🚨 Suspicious Payload detected from {packet_info.get('src_ip')}")
        
        return detected

# =============================================================================
# HIGH-PERFORMANCE IDS ENGINE
# =============================================================================

class HighPerformanceIDSEngine:
    """Main IDS engine optimized for high performance and attack detection"""
    def __init__(self, environment="testing"):
        logger.info("🛡️ Initializing High-Performance IDS Engine...")
        
        # Initialize detection rules - ALL OPTIMIZED FOR TESTING
        self.rules = [
            HighPerformancePortScanRule(),
            EnhancedDDoSDetectionRule(),
            HighPerformanceBruteForceRule(),
            HighPerformanceDNSTunnelingRule(),
            HighPerformanceReconRule(),
            SuspiciousPayloadRule(),
        ]
        
        self.total_alerts = 0
        self.yara_engine = None
        self.analysis_cache = {}
        self.cache_size_limit = 500  # Smaller cache for performance
        
        # Performance metrics
        self.metrics = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'cache_hits': 0,
            'processing_time': 0.0,
            'last_reset': time.time()
        }
        
        # Initialize YARA if available
        if YARA_AVAILABLE:
            try:
                self.yara_engine = integrate_yara_into_ids(self)
                logger.info("🔍 YARA engine initialized")
            except Exception as e:
                logger.error(f"❌ YARA initialization failed: {e}")
                self.yara_engine = None
        
        self._print_initialization_summary()
    
    def analyze_packet(self, packet_info, raw_data=None):
        """High-performance packet analysis"""
        start_time = time.time()
        triggered_alerts = []
        
        # Simplified caching for performance
        cache_key = f"{packet_info.get('src_ip')}:{packet_info.get('protocol')}:{packet_info.get('dst_port')}"
        
        # Analyze packet against all rules
        for rule in self.rules:
            if rule.enabled and rule.check(packet_info, raw_data):
                if rule.trigger():
                    alert = self._create_alert(rule, packet_info)
                    triggered_alerts.append(alert)
                    print(f"🚨 ALERT: {rule.name} - {packet_info.get('src_ip')} → {packet_info.get('dst_ip')}")
        
        # Update metrics
        self.metrics['packets_analyzed'] += 1
        self.metrics['alerts_generated'] += len(triggered_alerts)
        self.metrics['processing_time'] += time.time() - start_time
        
        # Reset metrics periodically
        if time.time() - self.metrics['last_reset'] > 60:
            self._reset_metrics()
        
        self.total_alerts += len(triggered_alerts)
        return triggered_alerts
    
    def _reset_metrics(self):
        """Reset metrics for fresh stats"""
        self.metrics = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'cache_hits': 0,
            'processing_time': 0.0,
            'last_reset': time.time()
        }
    
    def _create_alert(self, rule, packet_info):
        """Create standardized alert"""
        return {
            'id': self.total_alerts + 1,
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
    
    def _print_initialization_summary(self):
        """Print initialization summary"""
        print(f"📊 High-Performance IDS Engine Ready:")
        print(f"   • {len(self.rules)} detection rules loaded")
        print(f"   • Environment: {CONFIG['environment']} (attack detection optimized)")
        print(f"   • YARA: {'Available' if self.yara_engine else 'Not available'}")
        print(f"   • Whitelisting: DISABLED for testing")
        print(f"   • Thresholds: REDUCED for testing")
        print(f"   • Smart Filtering: {'Enabled' if SMART_FILTER_CONFIG['enable_smart_filtering'] else 'Disabled'}")

# =============================================================================
# HIGH-PERFORMANCE PACKET CAPTURE
# =============================================================================

class HighPerformancePacketCapture:
    """High-performance packet capture - 500+ pps"""
    def __init__(self):
        self.conn = None
        self.is_running = False
        self.ids_engine = HighPerformanceIDSEngine(CONFIG['environment'])
        # ADD SMART FILTERING
        self.packet_filter = SmartPacketFilter()
        self.packet_stats = {
            'total_packets': 0,
            'total_alerts': 0,
            'start_time': None,
            'dropped_packets': 0,
            'packets_per_second': 0,
            'last_rate_check': time.time()
        }
        
        # High-performance background processing
        self.processing_threads = []
        self.ui_update_thread = None
        self.num_processing_threads = 3  # Multiple processing threads
    
    def start_capture(self, interface_ip):
        """Start high-performance packet capture"""
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.conn.bind((interface_ip, 0))
            self.conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if sys.platform == "win32":
                self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.is_running = True
            self.packet_stats['start_time'] = datetime.now()
            
            # Start multiple background processing threads for high performance
            for i in range(self.num_processing_threads):
                thread = threading.Thread(target=self._background_processor, daemon=True, name=f"Processor-{i}")
                self.processing_threads.append(thread)
                thread.start()
            
            # Start UI update thread
            self.ui_update_thread = threading.Thread(target=self._high_performance_ui_updater, daemon=True)
            self.ui_update_thread.start()
            
            print(f"🚀 High-performance packet capture started on {interface_ip}")
            print(f"📊 Processing threads: {self.num_processing_threads}")
            print(f"⚡ Target performance: 500+ packets/second")
            print(f"🛡️ Smart filtering: {'Enabled' if SMART_FILTER_CONFIG['enable_smart_filtering'] else 'Disabled'}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start capture: {e}")
            return False, str(e)
    
    def capture_packets(self):
        """Main packet capture loop - optimized for speed"""
        print("🔍 Starting high-performance packet analysis...")
        
        packet_count = 0
        last_rate_time = time.time()
        
        while self.is_running:
            try:
                raw_data, addr = self.conn.recvfrom(65535)
                packet_count += 1
                self.packet_stats['total_packets'] += 1
                
                # Calculate packets per second
                current_time = time.time()
                if current_time - last_rate_time >= 1.0:
                    self.packet_stats['packets_per_second'] = packet_count
                    packet_count = 0
                    last_rate_time = current_time
                
                # Parse packet quickly
                packet_info = self.parse_packet_fast(raw_data, self.packet_stats['total_packets'])
                
                # Add to queue for background processing - non-blocking
                try:
                    packet_queue.put((packet_info, raw_data), block=False)
                except queue.Full:
                    self.packet_stats['dropped_packets'] += 1
                
            except Exception as e:
                if self.is_running:
                    print(f"❌ Capture error: {e}")
                    socketio.emit('capture_error', {'error': str(e)})
                break
    
    def _background_processor(self):
        """Background thread for high-speed packet processing with smart filtering"""
        while self.is_running:
            try:
                packet_info, raw_data = packet_queue.get(timeout=1)
                
                # SMART FILTERING CHECK - Skip unwanted packets
                if not self.packet_filter.should_process_packet(packet_info, raw_data):
                    continue  # Skip this packet
                
                # IDS analysis (only for filtered packets)
                packet_alerts = self.ids_engine.analyze_packet(packet_info, raw_data)
                
                # Update network topology
                update_network_topology(packet_info)
                
                # Add packet to display queue
                captured_packets.append(packet_info)
                
                # Handle alerts
                for alert in packet_alerts:
                    alerts.append(alert)
                    self.packet_stats['total_alerts'] += 1
                    
                    # Mark threat IPs
                    if alert.get('src_ip'):
                        mark_threat_ip(alert['src_ip'])
                    if alert.get('dst_ip'):
                        mark_threat_ip(alert['dst_ip'])
                    
                    try:
                        alert_queue.put(alert, block=False)
                    except queue.Full:
                        pass
                    
            except queue.Empty:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"Background processing error: {e}")
    
    def _high_performance_ui_updater(self):
        """High-performance UI updater - 500+ pps capable with filter stats"""
        while self.is_running:
            try:
                time.sleep(CONFIG['update_interval'])  # 0.1 seconds
                
                # Batch packet updates - larger batches
                packets_to_send = []
                for _ in range(min(CONFIG['batch_size'], len(captured_packets))):
                    if captured_packets:
                        packets_to_send.append(captured_packets[-_-1])
                
                if packets_to_send:
                    socketio.emit('packet_batch', packets_to_send[::-1])  # Reverse to show newest first
                
                # Batch alert updates
                alerts_to_send = []
                alert_count = 0
                while not alert_queue.empty() and alert_count < CONFIG['batch_size']:
                    try:
                        alert = alert_queue.get_nowait()
                        alerts_to_send.append(alert)
                        alert_count += 1
                    except queue.Empty:
                        break
                
                if alerts_to_send:
                    socketio.emit('alert_batch', alerts_to_send)
                
                # Send enhanced stats WITH filter statistics
                stats = {
                    'packets': self.packet_stats['total_packets'],
                    'alerts': self.packet_stats['total_alerts'],
                    'dropped': self.packet_stats['dropped_packets'],
                    'queue_size': packet_queue.qsize(),
                    'packets_per_second': self.packet_stats['packets_per_second'],
                    'processing_threads': len([t for t in self.processing_threads if t.is_alive()]),
                    'ids_metrics': self.ids_engine.metrics,
                    'filter_stats': self.packet_filter.get_filter_stats()
                }
                socketio.emit('stats_update', stats)
                
            except Exception as e:
                if self.is_running:
                    print(f"UI update error: {e}")
    
    def parse_packet_fast(self, data, packet_num):
        """Ultra-fast packet parsing - minimal processing"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        try:
            # Quick IP header parse
            if len(data) < 20:
                return self._create_minimal_packet(packet_num, timestamp, len(data))
            
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
            
            # Quick transport layer parse
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
                packet_info['flags'] = ','.join(flag_names) if flag_names else 'None'
                
            elif ip_header[6] == 17 and len(data) >= header_length + 8:  # UDP
                udp_header = struct.unpack('!HHHH', data[header_length:header_length+8])
                packet_info['src_port'] = udp_header[0]
                packet_info['dst_port'] = udp_header[1]
            
            return packet_info
            
        except Exception as e:
            return self._create_minimal_packet(packet_num, timestamp, len(data), str(e))
    
    def _create_minimal_packet(self, packet_num, timestamp, size, error=None):
        """Create minimal packet info for errors"""
        return {
            'id': packet_num,
            'timestamp': timestamp,
            'src_ip': 'unknown',
            'dst_ip': 'unknown',
            'protocol': 'Unknown',
            'size': size,
            'error': error
        }
    
    def get_protocol_name(self, protocol_num):
        """Fast protocol name lookup"""
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP'}
        return protocols.get(protocol_num, f'Protocol-{protocol_num}')
    
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
        except Exception as e:
            logger.error(f"❌ Error getting interfaces: {e}")
        
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
        
        print("⏹️ High-performance packet capture stopped")

# =============================================================================
# FLASK ROUTES - OPTIMIZED
# =============================================================================

packet_capture = HighPerformancePacketCapture()

@app.route('/')
def index():
    return render_template('index_optimized.html')

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
    
    # Clear queues
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            break
    
    while not alert_queue.empty():
        try:
            alert_queue.get_nowait()
        except queue.Empty:
            break
    
    # Start capture
    result = packet_capture.start_capture(interface_ip)
    if result is True:
        is_capturing = True
        capture_thread = threading.Thread(target=packet_capture.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        status = "with YARA support" if YARA_AVAILABLE else "traditional rules only"
        filter_status = "with Smart Filtering" if SMART_FILTER_CONFIG['enable_smart_filtering'] else ""
        return jsonify({
            'success': True, 
            'message': f'High-Performance IDS started {status} {filter_status}',
            'environment': CONFIG['environment'],
            'performance_target': '500+ packets/second',
            'smart_filtering': SMART_FILTER_CONFIG['enable_smart_filtering']
        })
    else:
        return jsonify({'success': False, 'message': f'Failed to start: {result[1]}'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing
    
    if not is_capturing:
        return jsonify({'success': False, 'message': 'No capture running'})
    
    is_capturing = False
    packet_capture.stop_capture()
    
    return jsonify({
        'success': True, 
        'message': 'High-Performance IDS stopped',
        'stats': packet_capture.packet_stats
    })

@app.route('/packets')
def get_packets():
    return jsonify(list(captured_packets)[-100:])

@app.route('/alerts')
def get_alerts():
    return jsonify(list(alerts))

@app.route('/rules')
def get_rules():
    """Get IDS rules status"""
    rule_status = []
    
    for rule in packet_capture.ids_engine.rules:
        status = {
            'name': rule.name,
            'description': rule.description,
            'severity': rule.severity,
            'enabled': rule.enabled,
            'trigger_count': rule.trigger_count,
            'last_triggered': rule.last_triggered.strftime("%H:%M:%S") if rule.last_triggered else None,
            'type': 'Traditional'
        }
        rule_status.append(status)
    
    return jsonify(rule_status)

@app.route('/performance')
def get_performance():
    """Get performance metrics"""
    return jsonify({
        'ids_metrics': packet_capture.ids_engine.metrics,
        'queue_sizes': {
            'packets': packet_queue.qsize(),
            'alerts': alert_queue.qsize()
        },
        'memory_usage': {
            'packets': len(captured_packets),
            'alerts': len(alerts)
        },
        'capture_stats': packet_capture.packet_stats
    })

# NEW SMART FILTERING ROUTES
@app.route('/api/filter/stats')
def get_filter_stats():
    """Get smart filtering statistics"""
    if hasattr(packet_capture, 'packet_filter'):
        stats = packet_capture.packet_filter.get_filter_stats()
        return jsonify(stats)
    return jsonify({'error': 'Filter not available'})

@app.route('/api/filter/config', methods=['POST'])
def update_filter_config():
    """Update smart filtering configuration"""
    data = request.get_json()
    
    if 'enable_smart_filtering' in data:
        SMART_FILTER_CONFIG['enable_smart_filtering'] = data['enable_smart_filtering']
    
    if 'enable_test_prioritization' in data:
        SMART_FILTER_CONFIG['test_mode']['enable_test_prioritization'] = data['enable_test_prioritization']
    
    return jsonify({'success': True, 'config': SMART_FILTER_CONFIG})

# =============================================================================
# WEBSOCKET HANDLERS
# =============================================================================

@socketio.on('connect')
def handle_connect():
    status = "with YARA support" if YARA_AVAILABLE else "(YARA not available)"
    filter_status = "Smart Filtering Enabled" if SMART_FILTER_CONFIG['enable_smart_filtering'] else "Smart Filtering Disabled"
    emit('connected', {
        'message': f'Connected to High-Performance IDS server {status} - {filter_status}',
        'environment': CONFIG['environment'],
        'config': CONFIG,
        'performance_info': 'Optimized for 500+ packets/second with attack detection and MS Teams filtering'
    })

@socketio.on('disconnect')
def handle_disconnect():
    pass

# =============================================================================
# MAIN APPLICATION
# =============================================================================

@app.route('/topology')
def topology_page():
    """Serve the network topology visualization page"""
    return render_template('network_topology.html')

@app.route('/api/topology/data')
def get_topology_data():
    """Get current network topology data"""
    return jsonify(get_network_topology_data())

@app.route('/api/topology/config', methods=['POST'])
def topology_config():
    """Update topology configuration"""
    data = request.get_json()
    with topology_lock:
        if 'max_nodes' in data:
            network_topology['max_nodes'] = int(data['max_nodes'])
    return jsonify({'success': True})

@app.route('/api/topology/cleanup', methods=['POST'])
def manual_topology_cleanup():
    """Manually trigger topology cleanup - FIXED version"""
    try:
        with topology_lock:
            current_time = time.time()
            # Use a more aggressive cleanup threshold for manual cleanup (2x normal interval)
            cleanup_threshold = current_time - (network_topology['cleanup_interval'] * 2)
            
            # FIX 1: Cleanup nodes with proper iteration
            nodes_to_remove = []
            for ip, node_data in list(network_topology['nodes'].items()):
                last_seen = node_data.get('last_seen')
                if not last_seen or last_seen < cleanup_threshold:
                    nodes_to_remove.append(ip)
            
            # Remove nodes
            nodes_removed = 0
            for ip in nodes_to_remove:
                if ip in network_topology['nodes']:
                    del network_topology['nodes'][ip]
                    nodes_removed += 1
                network_topology['threat_ips'].discard(ip)
            
            # FIX 2: Cleanup edges with proper iteration
            edges_to_remove = []
            for edge_key, edge_data in list(network_topology['edges'].items()):
                last_seen = edge_data.get('last_seen')
                if not last_seen or last_seen < cleanup_threshold:
                    edges_to_remove.append(edge_key)
                else:
                    # Also remove edges where nodes no longer exist
                    try:
                        src_ip, dst_ip = edge_key.split('->', 1)
                        if src_ip not in network_topology['nodes'] or dst_ip not in network_topology['nodes']:
                            edges_to_remove.append(edge_key)
                    except ValueError:
                        edges_to_remove.append(edge_key)  # Remove malformed edges
            
            # Remove edges
            edges_removed = 0
            for edge_key in edges_to_remove:
                if edge_key in network_topology['edges']:
                    del network_topology['edges'][edge_key]
                    edges_removed += 1
            
            # FIX 3: Cleanup connection stats
            connections_to_remove = []
            for connection_key in list(network_topology['connection_stats'].keys()):
                if len(connection_key) >= 2:
                    ip1, ip2 = connection_key[0], connection_key[1]
                    # Remove if either IP no longer exists
                    if ip1 not in network_topology['nodes'] or ip2 not in network_topology['nodes']:
                        connections_to_remove.append(connection_key)
                else:
                    # Remove malformed connection keys
                    connections_to_remove.append(connection_key)
            
            # Remove connections
            connections_removed = 0
            for connection_key in connections_to_remove:
                if connection_key in network_topology['connection_stats']:
                    del network_topology['connection_stats'][connection_key]
                    connections_removed += 1
            
            # FIX 4: Also cleanup orphaned threat IPs
            threat_ips_to_remove = []
            for threat_ip in list(network_topology['threat_ips']):
                if threat_ip not in network_topology['nodes']:
                    threat_ips_to_remove.append(threat_ip)
            
            threats_removed = 0
            for threat_ip in threat_ips_to_remove:
                network_topology['threat_ips'].discard(threat_ip)
                threats_removed += 1
            
            # FIX 5: Reset node connections (remove references to deleted nodes)
            for ip, node_data in network_topology['nodes'].items():
                if 'connections' in node_data and isinstance(node_data['connections'], set):
                    # Remove connections to nodes that no longer exist
                    valid_connections = {conn for conn in node_data['connections'] 
                                       if conn in network_topology['nodes']}
                    node_data['connections'] = valid_connections
        
        cleanup_summary = {
            'nodes_removed': nodes_removed,
            'edges_removed': edges_removed,
            'connections_removed': connections_removed,
            'threats_removed': threats_removed,
            'remaining_nodes': len(network_topology['nodes']),
            'remaining_edges': len(network_topology['edges']),
            'remaining_connections': len(network_topology['connection_stats']),
            'remaining_threats': len(network_topology['threat_ips'])
        }
        
        print(f"🧹 Manual cleanup completed: {cleanup_summary}")
        
        return jsonify({
            'success': True, 
            'message': f'Cleanup completed: {nodes_removed} nodes, {edges_removed} edges, {connections_removed} connections removed',
            'details': cleanup_summary
        })
        
    except Exception as e:
        print(f"Cleanup error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e), 'details': 'Check server logs for full error'})

@socketio.on('topology_subscribe')
def handle_topology_subscription():
    """Handle client subscription to topology updates"""
    emit('topology_subscribed', {'message': 'Subscribed to topology updates'})

# Add this function and thread to app.py to enable automatic cleanup
def automatic_topology_cleanup():
    """Background thread that automatically cleans up old topology data"""
    print("🧹 Starting automatic topology cleanup thread...")
    
    while True:
        try:
            # Wait for cleanup interval (e.g., every 60 seconds)
            time.sleep(60)  # Run cleanup every minute
            
            with topology_lock:
                current_time = time.time()
                cleanup_threshold = current_time - network_topology['cleanup_interval']
                
                # Count items before cleanup
                nodes_before = len(network_topology['nodes'])
                edges_before = len(network_topology['edges'])
                connections_before = len(network_topology['connection_stats'])
                
                # Cleanup old nodes
                nodes_to_remove = []
                for ip, node_data in list(network_topology['nodes'].items()):
                    last_seen = node_data.get('last_seen')
                    if not last_seen or last_seen < cleanup_threshold:
                        nodes_to_remove.append(ip)
                
                for ip in nodes_to_remove:
                    if ip in network_topology['nodes']:
                        del network_topology['nodes'][ip]
                    network_topology['threat_ips'].discard(ip)
                
                # Cleanup old edges
                edges_to_remove = []
                for edge_key, edge_data in list(network_topology['edges'].items()):
                    last_seen = edge_data.get('last_seen')
                    if not last_seen or last_seen < cleanup_threshold:
                        edges_to_remove.append(edge_key)
                    else:
                        # Remove edges where nodes no longer exist
                        try:
                            src_ip, dst_ip = edge_key.split('->', 1)
                            if src_ip not in network_topology['nodes'] or dst_ip not in network_topology['nodes']:
                                edges_to_remove.append(edge_key)
                        except ValueError:
                            edges_to_remove.append(edge_key)
                
                for edge_key in edges_to_remove:
                    if edge_key in network_topology['edges']:
                        del network_topology['edges'][edge_key]
                
                # Cleanup orphaned connections
                connections_to_remove = []
                for connection_key in list(network_topology['connection_stats'].keys()):
                    if len(connection_key) >= 2:
                        ip1, ip2 = connection_key[0], connection_key[1]
                        if ip1 not in network_topology['nodes'] or ip2 not in network_topology['nodes']:
                            connections_to_remove.append(connection_key)
                
                for connection_key in connections_to_remove:
                    if connection_key in network_topology['connection_stats']:
                        del network_topology['connection_stats'][connection_key]
                
                # Log cleanup results if significant
                nodes_removed = len(nodes_to_remove)
                edges_removed = len(edges_to_remove)
                connections_removed = len(connections_to_remove)
                
                if nodes_removed > 0 or edges_removed > 0 or connections_removed > 0:
                    print(f"🧹 Auto-cleanup: -{nodes_removed} nodes, -{edges_removed} edges, -{connections_removed} connections")
                    print(f"📊 Remaining: {len(network_topology['nodes'])} nodes, {len(network_topology['edges'])} edges")
                
        except Exception as e:
            print(f"❌ Auto-cleanup error: {e}")
            # Continue running even if there's an error
            continue

if __name__ == '__main__':
    print("=" * 80)
    print("🛡️  HIGH-PERFORMANCE INTRUSION DETECTION SYSTEM (ENHANCED)")
    print("=" * 80)
    print("Performance Optimizations:")
    print("• Target: 500+ packets/second processing")
    print("• Multiple background processing threads")
    print("• Optimized packet parsing and analysis")
    print("• Large batches and fast UI updates")
    print("• Reduced rate limiting for testing")
    print("Attack Detection Optimizations:")
    print("• FIXED: DDoS rule is now more specific to avoid false positives")
    print("• REMOVED IP whitelisting (detects all external IPs)")
    print("• REDUCED detection thresholds for testing")
    print("• Enhanced logging for debugging")
    print("• Optimized for test script IP ranges")
    print("Smart Filtering Features:")
    print(f"• MS Teams Traffic Filtering: {'Enabled' if SMART_FILTER_CONFIG['enable_smart_filtering'] else 'Disabled'}")
    print(f"• Test Traffic Prioritization: {'Enabled' if SMART_FILTER_CONFIG['test_mode']['enable_test_prioritization'] else 'Disabled'}")
    print("• Communication Apps Bypass: Teams, Zoom, WebEx")
    print("• Rate Limiting: High-volume legitimate protocols")
    print("• Demonstration Mode: Optimized for live presentations")
    if YARA_AVAILABLE:
        print("• YARA pattern matching enabled")
    print("=" * 80)
    print(f"🌐 Web Interface: http://localhost:5000")
    print(f"🌐 Network Topology: http://localhost:5000/topology")
    print(f"🔧 Environment: {CONFIG['environment']}")
    print(f"📊 Batch Size: {CONFIG['batch_size']}")
    print(f"⏱️  Update Interval: {CONFIG['update_interval']}s")
    print(f"🎯 DDoS Threshold: 100 packets/30s")
    print(f"🎯 Port Scan Threshold: 15 ports/60s")
    print(f"🎯 Brute Force Threshold: 30 attempts/5min")
    print(f"🎯 DNS Tunneling Threshold: 50 queries/60s")
    print("Smart Filter Configuration:")
    print(f"• Bypass MS Teams ports: {SMART_FILTER_CONFIG['bypass_applications']['teams_ports']}")
    print(f"• Test target IPs: {SMART_FILTER_CONFIG['test_mode']['test_ips']}")
    print(f"• Rate limit: {SMART_FILTER_CONFIG['bypass_applications']['max_packets_per_second']} pps per app")
    print("=" * 80)
    print("⚠️  Remember to run as Administrator/sudo for packet capture!")
    print("🧪 Ready for attack testing with MS Teams noise filtering!")
    print("🎥 Demonstration mode optimized - Smart filtering enabled!")
    print("=" * 80)

    # Start automatic cleanup thread
    cleanup_thread = threading.Thread(target=automatic_topology_cleanup, daemon=True)
    cleanup_thread.start()
    print("✅ Automatic topology cleanup thread started")
    
    try:
        socketio.run(app, debug=CONFIG['debug_mode'], host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 High-Performance IDS shutdown requested")
        if is_capturing:
            packet_capture.stop_capture()
        print("✅ High-Performance IDS stopped cleanly")
    except Exception as e:
        print(f"❌ Critical error: {e}")
        if is_capturing:
            packet_capture.stop_capture()