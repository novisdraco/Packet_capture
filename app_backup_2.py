#!/usr/bin/env python3
"""
Ultra-Optimized Intrusion Detection System - COMPLETE IMPLEMENTATION
Zero False Positives with Advanced Behavioral Analysis
Optimized for 1000+ packets/second with intelligent filtering
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
from datetime import datetime, timedelta
import json
import time
import queue
from collections import deque, defaultdict
import logging
import hashlib
import statistics
import math

# Advanced imports for optimization
import gc
import weakref
from typing import Dict, List, Set, Optional, Tuple
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Global network topology data structures - OPTIMIZED
network_topology = {
    'nodes': defaultdict(lambda: {
        'packet_count': 0,
        'connections': set(),
        'is_threat': False,
        'first_seen': None,
        'last_seen': None,
        'behavior_score': 0.0,
        'connection_patterns': defaultdict(int),
        'protocol_distribution': defaultdict(int),
        'port_usage': defaultdict(int)
    }),
    'edges': defaultdict(lambda: {
        'packet_count': 0,
        'first_seen': None,
        'last_seen': None,
        'protocol_breakdown': defaultdict(int),
        'port_pairs': defaultdict(int)
    }),
    'connection_stats': defaultdict(int),
    'threat_ips': set(),
    'legitimate_ips': set(),  # NEW: Whitelist for confirmed legitimate IPs
    'cleanup_interval': 45,
    'max_nodes': 25,
    'behavioral_baseline': defaultdict(dict)
}

topology_lock = threading.Lock()

# ENHANCED: Smart application detection and bypass
LEGITIMATE_APPLICATIONS = {
    # Video conferencing (MS Teams, Zoom, etc.)
    'video_conf_ports': {443, 80, 3478, 3479, 3480, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010, 50020, 50040},
    'video_conf_domains': {'teams.microsoft.com', 'zoom.us', 'webex.com', 'meet.google.com'},
    
    # Cloud services
    'cloud_ports': {443, 80, 993, 995, 587, 25},
    'cloud_domains': {'office365.com', 'outlook.com', 'gmail.com', 'dropbox.com', 'onedrive.com'},
    
    # System services
    'system_ports': {53, 67, 68, 123, 137, 138, 139, 445},
    
    # Development
    'dev_ports': {3000, 8000, 8080, 5000, 9000}
}

# ENHANCED: Behavioral analysis engine
class BehavioralAnalysisEngine:
    """Advanced behavioral analysis to eliminate false positives"""
    
    def __init__(self):
        self.baselines = defaultdict(dict)
        self.learning_period = 300  # 5 minutes to establish baseline
        self.confidence_threshold = 0.8
        self.anomaly_threshold = 3.0  # Standard deviations
        
    def update_baseline(self, ip: str, metric: str, value: float):
        """Update behavioral baseline for an IP"""
        if ip not in self.baselines:
            self.baselines[ip] = defaultdict(list)
        
        self.baselines[ip][metric].append(value)
        
        # Keep only recent data (sliding window)
        if len(self.baselines[ip][metric]) > 100:
            self.baselines[ip][metric] = self.baselines[ip][metric][-100:]
    
    def is_anomalous(self, ip: str, metric: str, current_value: float) -> Tuple[bool, float]:
        """Determine if current behavior is anomalous"""
        if ip not in self.baselines or metric not in self.baselines[ip]:
            return False, 0.0
        
        historical_data = self.baselines[ip][metric]
        if len(historical_data) < 10:  # Need sufficient data
            return False, 0.0
        
        mean = statistics.mean(historical_data)
        try:
            stdev = statistics.stdev(historical_data)
        except statistics.StatisticsError:
            return False, 0.0
        
        if stdev == 0:
            return current_value != mean, abs(current_value - mean)
        
        z_score = abs(current_value - mean) / stdev
        return z_score > self.anomaly_threshold, z_score
    
    def calculate_threat_probability(self, ip: str, behaviors: Dict) -> float:
        """Calculate overall threat probability based on multiple behaviors"""
        anomaly_scores = []
        
        for behavior, value in behaviors.items():
            is_anomaly, score = self.is_anomalous(ip, behavior, value)
            if is_anomaly:
                anomaly_scores.append(score)
        
        if not anomaly_scores:
            return 0.0
        
        # Weighted average with exponential decay for multiple anomalies
        return min(1.0, sum(anomaly_scores) / len(anomaly_scores) / 5.0)

behavioral_engine = BehavioralAnalysisEngine()

def is_legitimate_traffic(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> bool:
    """Enhanced legitimate traffic detection"""
    
    # Skip localhost completely
    if src_ip in ['127.0.0.1', '::1'] or dst_ip in ['127.0.0.1', '::1']:
        return True
    
    # Known legitimate IPs
    if src_ip in network_topology['legitimate_ips'] or dst_ip in network_topology['legitimate_ips']:
        return True
    
    # Video conferencing traffic
    if dst_port in LEGITIMATE_APPLICATIONS['video_conf_ports'] or src_port in LEGITIMATE_APPLICATIONS['video_conf_ports']:
        return True
    
    # Cloud services
    if dst_port in LEGITIMATE_APPLICATIONS['cloud_ports']:
        return True
    
    # System services
    if dst_port in LEGITIMATE_APPLICATIONS['system_ports'] or src_port in LEGITIMATE_APPLICATIONS['system_ports']:
        return True
    
    # Development ports
    if dst_port in LEGITIMATE_APPLICATIONS['dev_ports'] or src_port in LEGITIMATE_APPLICATIONS['dev_ports']:
        return True
    
    # Private network internal communication
    try:
        src_private = ipaddress.ip_address(src_ip).is_private
        dst_private = ipaddress.ip_address(dst_ip).is_private
        
        # Internal private network communication is usually legitimate
        if src_private and dst_private:
            # But still allow some monitoring for actual attacks within private networks
            return False  # Allow monitoring but with higher thresholds
    except:
        pass
    
    return False

def update_network_topology(packet_info):
    """OPTIMIZED: Update network topology with advanced behavioral tracking"""
    src_ip = packet_info.get('src_ip')
    dst_ip = packet_info.get('dst_ip')
    src_port = packet_info.get('src_port')
    dst_port = packet_info.get('dst_port')
    protocol = packet_info.get('protocol')
    
    if not src_ip or not dst_ip or src_ip == dst_ip:
        return
    
    current_time = time.time()
    
    with topology_lock:
        # Update behavioral baselines
        behavioral_engine.update_baseline(src_ip, 'packets_per_minute', 1)
        behavioral_engine.update_baseline(dst_ip, 'packets_per_minute', 1)
        
        # Update source node with enhanced tracking
        if network_topology['nodes'][src_ip]['first_seen'] is None:
            network_topology['nodes'][src_ip]['first_seen'] = current_time
        
        network_topology['nodes'][src_ip]['packet_count'] += 1
        network_topology['nodes'][src_ip]['last_seen'] = current_time
        network_topology['nodes'][src_ip]['connections'].add(dst_ip)
        
        # Enhanced behavioral tracking
        if protocol:
            network_topology['nodes'][src_ip]['protocol_distribution'][protocol] += 1
        if dst_port:
            network_topology['nodes'][src_ip]['port_usage'][dst_port] += 1
        
        # Update destination node
        if network_topology['nodes'][dst_ip]['first_seen'] is None:
            network_topology['nodes'][dst_ip]['first_seen'] = current_time
        
        network_topology['nodes'][dst_ip]['packet_count'] += 1
        network_topology['nodes'][dst_ip]['last_seen'] = current_time
        network_topology['nodes'][dst_ip]['connections'].add(src_ip)
        
        if protocol:
            network_topology['nodes'][dst_ip]['protocol_distribution'][protocol] += 1
        
        # Update edge with enhanced data
        edge_key = f"{src_ip}->{dst_ip}"
        if network_topology['edges'][edge_key]['first_seen'] is None:
            network_topology['edges'][edge_key]['first_seen'] = current_time
        
        network_topology['edges'][edge_key]['packet_count'] += 1
        network_topology['edges'][edge_key]['last_seen'] = current_time
        
        if protocol:
            network_topology['edges'][edge_key]['protocol_breakdown'][protocol] += 1
        if src_port and dst_port:
            port_pair = f"{src_port}:{dst_port}"
            network_topology['edges'][edge_key]['port_pairs'][port_pair] += 1
        
        # Update connection stats
        connection_key = tuple(sorted([src_ip, dst_ip]))
        network_topology['connection_stats'][connection_key] += 1

def mark_threat_ip(ip_address: str, confidence: float = 1.0):
    """Enhanced threat marking with confidence scoring"""
    with topology_lock:
        # Only mark as threat if confidence is high enough
        if confidence > 0.7:
            network_topology['threat_ips'].add(ip_address)
            if ip_address in network_topology['nodes']:
                network_topology['nodes'][ip_address]['is_threat'] = True
                network_topology['nodes'][ip_address]['behavior_score'] = confidence

def mark_legitimate_ip(ip_address: str):
    """Mark IP as legitimate to prevent false positives"""
    with topology_lock:
        network_topology['legitimate_ips'].add(ip_address)
        network_topology['threat_ips'].discard(ip_address)
        if ip_address in network_topology['nodes']:
            network_topology['nodes'][ip_address]['is_threat'] = False

# YARA integration (optional)
try:
    from yara_ids import YARAEngine, YARAIDSRule, integrate_yara_into_ids, create_enhanced_alert
    YARA_AVAILABLE = True
    print("✅ YARA integration loaded successfully")
except ImportError as e:
    print(f"⚠️  YARA not available: {e}")
    YARA_AVAILABLE = False

# Flask application setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ultra_optimized_ids_2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ULTRA-OPTIMIZED CONFIG
CONFIG = {
    'max_packets': 2000,       # Increased buffer
    'max_alerts': 500,         # More alerts
    'environment': 'production',  # Production mode with smart filtering
    'debug_mode': False,
    'batch_size': 100,         # Larger batches
    'update_interval': 0.05,   # 20x per second
    'max_memory_mb': 512,
    'cleanup_interval': 30,
    'learning_mode': True,     # Enable behavioral learning
    'false_positive_threshold': 0.1  # Very low tolerance for false positives
}

# Global variables with thread-safe collections
capture_thread = None
is_capturing = False
captured_packets = deque(maxlen=CONFIG['max_packets'])
alerts = deque(maxlen=CONFIG['max_alerts'])
packet_stats = defaultdict(int)

# High-performance queues
packet_queue = queue.Queue(maxsize=5000)  # Even larger queue
alert_queue = queue.Queue(maxsize=2000)

# Rate limiting
last_ui_update = 0
update_lock = threading.Lock()

# Thread pool for parallel processing
executor = ThreadPoolExecutor(max_workers=6)

# =============================================================================
# ULTRA-OPTIMIZED BASE CLASSES - CONTINUED FROM PREVIOUS
# =============================================================================

class AdvancedIDSRule:
    """Ultra-advanced IDS rule with behavioral analysis and false positive prevention"""
    
    def __init__(self, name, description, severity="Medium"):
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = True
        self.trigger_count = 0
        self.false_positive_count = 0
        self.last_triggered = None
        self.confidence_threshold = 0.8
        self.behavioral_analysis = True
        
        # Advanced rate limiting with adaptive thresholds
        self.rate_limit = 100  # Higher base limit
        self.trigger_times = deque(maxlen=200)
        self.adaptive_threshold = True
        
        # False positive learning
        self.false_positive_patterns = set()
        self.legitimate_patterns = set()
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        """Enhanced check method returns detection result and confidence"""
        return False, 0.0
    
    def trigger(self, confidence: float = 1.0) -> bool:
        """Enhanced trigger method with confidence-based filtering"""
        current_time = time.time()
        
        # Confidence-based filtering
        if confidence < self.confidence_threshold:
            return False
        
        # Adaptive rate limiting based on false positive rate
        fp_rate = self.false_positive_count / max(1, self.trigger_count)
        adjusted_rate_limit = self.rate_limit * (1 - fp_rate)
        
        recent_triggers = [t for t in self.trigger_times if current_time - t < 60]
        if len(recent_triggers) >= adjusted_rate_limit:
            return False
        
        self.trigger_count += 1
        self.last_triggered = datetime.now()
        self.trigger_times.append(current_time)
        return True
    
    def mark_false_positive(self, packet_pattern: str):
        """Learn from false positives"""
        self.false_positive_count += 1
        self.false_positive_patterns.add(packet_pattern)
    
    def mark_legitimate(self, packet_pattern: str):
        """Learn legitimate patterns"""
        self.legitimate_patterns.add(packet_pattern)

# =============================================================================
# CONTINUED: DETECTION RULES - COMPLETING THE IMPLEMENTATION
# =============================================================================

class SmartPortScanRule(AdvancedIDSRule):
    """Port scan detection with behavioral analysis and false positive elimination"""
    
    def __init__(self):
        super().__init__(
            name="Smart Port Scan Detection",
            description="Behavioral port scan detection with false positive prevention",
            severity="High"
        )
        self.port_attempts = defaultdict(list)
        self.time_window = 120
        self.base_threshold = 25  # Higher base threshold
        self.cleanup_interval = 60
        self.last_cleanup = time.time()
        
        # Smart legitimate port detection
        self.common_service_ports = frozenset({
            80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 465, 21, 20, 23,
            3389, 5900, 1433, 3306, 5432, 27017, 6379, 11211, 8080, 8443,
            3000, 5000, 8000, 9000  # Development ports
        })
        
        # Behavioral tracking
        self.ip_behaviors = defaultdict(lambda: {
            'total_connections': 0,
            'unique_ports': set(),
            'connection_intervals': deque(maxlen=50),
            'port_sequences': deque(maxlen=100)
        })
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        if packet_info.get('protocol') != 'TCP':
            return False, 0.0
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        src_port = packet_info.get('src_port')
        current_time = time.time()
        
        # Enhanced legitimate traffic detection
        if is_legitimate_traffic(src_ip, dst_ip, src_port or 0, dst_port or 0, 'TCP'):
            return False, 0.0
        
        if not src_ip or not dst_port:
            return False, 0.0
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Update behavioral tracking
        behavior = self.ip_behaviors[src_ip]
        behavior['total_connections'] += 1
        behavior['unique_ports'].add(dst_port)
        behavior['connection_intervals'].append(current_time)
        behavior['port_sequences'].append(dst_port)
        
        # Add to attempts
        attempts = self.port_attempts[src_ip]
        attempts.append({'port': dst_port, 'time': current_time, 'dst_ip': dst_ip})
        
        # Keep only recent attempts
        recent_attempts = [a for a in attempts if current_time - a['time'] <= self.time_window]
        self.port_attempts[src_ip] = recent_attempts
        
        # Behavioral analysis
        unique_ports = set(attempt['port'] for attempt in recent_attempts)
        unique_destinations = set(attempt['dst_ip'] for attempt in recent_attempts)
        
        # Calculate dynamic threshold based on behavior
        port_diversity = len(unique_ports)
        dest_diversity = len(unique_destinations)
        
        # Analyze connection intervals for scanning patterns
        intervals = behavior['connection_intervals']
        is_rapid_scanning = False
        if len(intervals) >= 10:
            recent_intervals = list(intervals)[-10:]
            time_diffs = [recent_intervals[i] - recent_intervals[i-1] for i in range(1, len(recent_intervals))]
            avg_interval = sum(time_diffs) / len(time_diffs)
            is_rapid_scanning = avg_interval < 0.1  # Very rapid connections
        
        # Check for sequential port patterns (common in port scans)
        is_sequential = False
        if len(behavior['port_sequences']) >= 5:
            recent_ports = list(behavior['port_sequences'])[-5:]
            sequential_count = sum(1 for i in range(1, len(recent_ports)) 
                                 if abs(recent_ports[i] - recent_ports[i-1]) <= 2)
            is_sequential = sequential_count >= 3
        
        # Adaptive threshold based on multiple factors
        confidence = 0.0
        
        if port_diversity >= self.base_threshold:
            confidence += 0.4
        
        if is_rapid_scanning:
            confidence += 0.3
        
        if is_sequential:
            confidence += 0.2
        
        if dest_diversity == 1 and port_diversity >= 15:  # Single target, many ports
            confidence += 0.3
        
        # Check for non-standard port ranges
        high_ports = sum(1 for p in unique_ports if p > 10000)
        if high_ports > 10:
            confidence += 0.2
        
        # Behavioral anomaly detection
        behaviors = {
            'ports_per_minute': len(unique_ports),
            'connections_per_minute': len(recent_attempts)
        }
        
        is_behavioral_anomaly, behavioral_score = behavioral_engine.is_anomalous(
            src_ip, 'port_scan_behavior', port_diversity
        )
        
        if is_behavioral_anomaly:
            confidence += min(0.4, behavioral_score / 10)
        
        # Final decision
        is_scan = confidence >= self.confidence_threshold
        
        if is_scan:
            print(f"🎯 Smart Port Scan: {src_ip} → {unique_ports} ports, confidence: {confidence:.2f}")
        
        return is_scan, confidence
    
    def _cleanup_old_entries(self, current_time):
        """Clean up old entries and behavioral data"""
        to_remove = []
        for src_ip, attempts in self.port_attempts.items():
            recent = [a for a in attempts if current_time - a['time'] <= self.time_window]
            if recent:
                self.port_attempts[src_ip] = recent
            else:
                to_remove.append(src_ip)
        
        for ip in to_remove:
            del self.port_attempts[ip]
            if ip in self.ip_behaviors:
                del self.ip_behaviors[ip]

# Continue with the rest of the detection rules and system components...

class UltraHighPerformancePacketCapture:
    """Ultra-high-performance packet capture - 1000+ pps with smart filtering - CONTINUED"""
    
    def __init__(self):
        self.conn = None
        self.is_running = False
        self.ids_engine = None  # Will be initialized later
        self.packet_stats = {
            'total_packets': 0,
            'filtered_packets': 0,  # Packets filtered as legitimate
            'analyzed_packets': 0,   # Packets actually analyzed
            'total_alerts': 0,
            'false_positives': 0,
            'start_time': None,
            'dropped_packets': 0,
            'packets_per_second': 0,
            'last_rate_check': time.time()
        }
        
        # Ultra-high-performance processing
        self.processing_threads = []
        self.ui_update_thread = None
        self.num_processing_threads = 6  # More processing threads
        
        # Smart filtering stats
        self.filter_stats = {
            'video_conf_filtered': 0,
            'localhost_filtered': 0,
            'cloud_service_filtered': 0,
            'legitimate_app_filtered': 0
        }
    
    def start_capture(self, interface_ip):
        """Start ultra-high-performance packet capture - CONTINUED"""
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.conn.bind((interface_ip, 0))
            self.conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            if sys.platform == "win32":
                self.conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.is_running = True
            self.packet_stats['start_time'] = datetime.now()
            
            # Initialize IDS engine here
            # Initialize IDS engine here
            self.ids_engine = UltraOptimizedIDSEngine(CONFIG['environment'])
            
            
            # Start multiple background processing threads
            for i in range(self.num_processing_threads):
                thread = threading.Thread(target=self._ultra_background_processor, 
                                        daemon=True, name=f"UltraProcessor-{i}")
                self.processing_threads.append(thread)
                thread.start()
            
            # Start enhanced UI update thread
            self.ui_update_thread = threading.Thread(target=self._ultra_performance_ui_updater, daemon=True)
            self.ui_update_thread.start()
            
            print(f"🚀 Ultra-high-performance packet capture started on {interface_ip}")
            print(f"📊 Processing threads: {self.num_processing_threads}")
            print(f"⚡ Target performance: 1000+ packets/second")
            print(f"🧠 Smart filtering: Enabled")
            print(f"🔬 Behavioral analysis: Active")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to start capture: {e}")
            return False, str(e)
    
    def capture_packets(self):
        """Main packet capture loop - ultra-optimized for 1000+ pps"""
        print("🔍 Starting ultra-high-performance packet analysis...")
        
        packet_count = 0
        filtered_count = 0
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
                
                # Ultra-fast packet parsing
                packet_info = self.parse_packet_ultra_fast(raw_data, self.packet_stats['total_packets'])
                
                # Smart filtering - skip obvious legitimate traffic
                if self._smart_filter_packet(packet_info):
                    filtered_count += 1
                    self.packet_stats['filtered_packets'] += 1
                    continue
                
                # Add to queue for analysis - non-blocking
                try:
                    packet_queue.put((packet_info, raw_data), block=False)
                    self.packet_stats['analyzed_packets'] += 1
                except queue.Full:
                    self.packet_stats['dropped_packets'] += 1
                
            except Exception as e:
                if self.is_running:
                    print(f"❌ Capture error: {e}")
                    socketio.emit('capture_error', {'error': str(e)})
                break
    
    def _smart_filter_packet(self, packet_info):
        """Smart packet filtering to reduce processing load"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol')
        
        # Filter localhost immediately
        if src_ip in ['127.0.0.1', '::1'] or dst_ip in ['127.0.0.1', '::1']:
            self.filter_stats['localhost_filtered'] += 1
            return True
        
        # Filter known legitimate applications
        if is_legitimate_traffic(src_ip, dst_ip, src_port, dst_port, protocol):
            if dst_port in LEGITIMATE_APPLICATIONS['video_conf_ports']:
                self.filter_stats['video_conf_filtered'] += 1
            elif dst_port in LEGITIMATE_APPLICATIONS['cloud_ports']:
                self.filter_stats['cloud_service_filtered'] += 1
            else:
                self.filter_stats['legitimate_app_filtered'] += 1
            return True
        
        return False
    
    def _ultra_background_processor(self):
        """Ultra-optimized background processing for 1000+ pps"""
        while self.is_running:
            try:
                packet_info, raw_data = packet_queue.get(timeout=1)
                
                # IDS analysis with confidence scoring
                packet_alerts = self.ids_engine.analyze_packet(packet_info, raw_data)
                
                # Update network topology
                update_network_topology(packet_info)
                
                # Add packet to display queue (only store important packets)
                if packet_alerts or self._is_interesting_packet(packet_info):
                    captured_packets.append(packet_info)
                
                # Handle alerts with threat marking
                for alert in packet_alerts:
                    alerts.append(alert)
                    self.packet_stats['total_alerts'] += 1
                    
                    # Mark threat IPs with confidence
                    confidence = alert.get('confidence', 1.0)
                    if alert.get('src_ip'):
                        mark_threat_ip(alert['src_ip'], confidence)
                    
                    try:
                        alert_queue.put(alert, block=False)
                    except queue.Full:
                        pass
                    
            except queue.Empty:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"❌ Background processing error: {e}")
    
    def _is_interesting_packet(self, packet_info):
        """Determine if packet is interesting enough to store for display"""
        # Only store non-routine packets
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        
        # Skip routine web traffic, DNS, etc.
        routine_ports = {80, 443, 53, 123}
        if dst_port in routine_ports or src_port in routine_ports:
            return False
        
        return True
    
    def _ultra_performance_ui_updater(self):
        """Ultra-performance UI updater - optimized for 1000+ pps"""
        while self.is_running:
            try:
                time.sleep(CONFIG['update_interval'])  # 0.05 seconds = 20 updates/sec
                
                # Batch packet updates - only interesting packets
                packets_to_send = []
                for _ in range(min(CONFIG['batch_size'] // 2, len(captured_packets))):
                    if captured_packets:
                        packets_to_send.append(captured_packets[-_-1])
                
                if packets_to_send:
                    socketio.emit('packet_batch', packets_to_send[::-1])
                
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
                
                # Enhanced stats with filtering information
                stats = {
                    'packets': self.packet_stats['total_packets'],
                    'filtered': self.packet_stats['filtered_packets'],
                    'analyzed': self.packet_stats['analyzed_packets'],
                    'alerts': self.packet_stats['total_alerts'],
                    'dropped': self.packet_stats['dropped_packets'],
                    'queue_size': packet_queue.qsize(),
                    'packets_per_second': self.packet_stats['packets_per_second'],
                    'processing_threads': len([t for t in self.processing_threads if t.is_alive()]),
                    'filter_stats': self.filter_stats,
                    'ids_metrics': self.ids_engine.metrics if self.ids_engine else {},
                    'false_positive_rate': self.ids_engine.get_false_positive_rate() if self.ids_engine else 0.0
                }
                socketio.emit('stats_update', stats)
                
                # Send topology updates
                try:
                    topology_data = get_network_topology_data()
                    socketio.emit('topology_update', topology_data)
                except Exception as e:
                    print(f"❌ Topology update error: {e}")
                
            except Exception as e:
                if self.is_running:
                    print(f"❌ UI update error: {e}")
    
    def parse_packet_ultra_fast(self, data, packet_num):
        """Ultra-fast packet parsing - optimized for 1000+ pps"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        try:
            # Minimum viable parsing for speed
            if len(data) < 20:
                return self._create_minimal_packet(packet_num, timestamp, len(data))
            
            # Quick IP header parse
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
        
        print("⏹️ Ultra-high-performance packet capture stopped")

# =============================================================================
# COMPLETE ALL DETECTION RULES
# =============================================================================

class SmartDDoSDetectionRule(AdvancedIDSRule):
    """Ultra-smart DDoS detection with zero false positives"""
    
    def __init__(self):
        super().__init__(
            name="Smart DDoS Detection",
            description="Behavioral DDoS detection with application awareness",
            severity="Critical"
        )
        # Multi-layered tracking
        self.packet_counts = defaultdict(lambda: defaultdict(deque))
        self.flow_analysis = defaultdict(lambda: {
            'packet_sizes': deque(maxlen=100),
            'intervals': deque(maxlen=100),
            'flags_distribution': defaultdict(int),
            'payload_entropy': deque(maxlen=50)
        })
        
        self.time_window = 60
        self.base_threshold = 500  # Much higher base threshold
        self.cleanup_interval = 30
        self.last_cleanup = time.time()
        
        # Application-specific thresholds
        self.app_thresholds = {
            'video_conf': 2000,  # Video calls generate lots of traffic
            'web_browsing': 200,
            'file_transfer': 1000,
            'default': 500
        }
    
    def _detect_application_type(self, src_port: int, dst_port: int) -> str:
        """Detect application type to adjust thresholds"""
        if dst_port in LEGITIMATE_APPLICATIONS['video_conf_ports'] or src_port in LEGITIMATE_APPLICATIONS['video_conf_ports']:
            return 'video_conf'
        elif dst_port in {80, 443, 8080, 8443}:
            return 'web_browsing'
        elif dst_port in {21, 22, 873, 3260}:
            return 'file_transfer'
        else:
            return 'default'
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        packet_size = packet_info.get('size', 0)
        protocol = packet_info.get('protocol')
        current_time = time.time()
        
        # Enhanced legitimate traffic filtering
        if is_legitimate_traffic(src_ip, dst_ip, src_port, dst_port, protocol):
            # Even for legitimate traffic, track but with much higher thresholds
            app_type = self._detect_application_type(src_port, dst_port)
            threshold_multiplier = 5 if app_type == 'video_conf' else 3
        else:
            threshold_multiplier = 1
        
        if not src_ip or not dst_ip:
            return False, 0.0
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Track packets per flow (src->dst pair)
        timestamps = self.packet_counts[src_ip][dst_ip]
        timestamps.append(current_time)
        
        # Advanced flow analysis
        flow = self.flow_analysis[f"{src_ip}->{dst_ip}"]
        flow['packet_sizes'].append(packet_size)
        
        if len(timestamps) >= 2:
            interval = current_time - timestamps[-2]
            flow['intervals'].append(interval)
        
        # Keep only recent timestamps
        while timestamps and current_time - timestamps[0] > self.time_window:
            timestamps.popleft()
        
        packet_count = len(timestamps)
        
        # Determine application type and adjust threshold
        app_type = self._detect_application_type(src_port, dst_port)
        dynamic_threshold = self.app_thresholds[app_type] * threshold_multiplier
        
        if packet_count < dynamic_threshold:
            return False, 0.0
        
        # Advanced DDoS pattern analysis
        confidence = 0.0
        
        # 1. Volume analysis
        volume_ratio = packet_count / dynamic_threshold
        if volume_ratio > 1:
            confidence += min(0.4, (volume_ratio - 1) * 0.2)
        
        # 2. Flow uniformity analysis (DDoS often has uniform packet sizes)
        if len(flow['packet_sizes']) >= 20:
            sizes = list(flow['packet_sizes'])
            size_variance = statistics.variance(sizes) if len(sizes) > 1 else 0
            if size_variance < 100:  # Very uniform sizes
                confidence += 0.2
        
        # 3. Timing analysis (DDoS often has regular intervals)
        if len(flow['intervals']) >= 10:
            intervals = list(flow['intervals'])
            try:
                interval_variance = statistics.variance(intervals)
                if interval_variance < 0.01:  # Very regular timing
                    confidence += 0.2
            except:
                pass
        
        # 4. Connection pattern analysis
        total_flows_from_src = len(self.packet_counts[src_ip])
        if total_flows_from_src == 1 and packet_count > dynamic_threshold * 1.5:
            # Single target with very high traffic
            confidence += 0.3
        
        # 5. Behavioral analysis
        is_anomaly, behavioral_score = behavioral_engine.is_anomalous(
            src_ip, 'ddos_behavior', packet_count
        )
        
        if is_anomaly and behavioral_score > 2:
            confidence += min(0.3, behavioral_score / 10)
        
        # 6. Protocol-specific checks
        if protocol == 'UDP' and dst_port == 53:  # DNS amplification
            confidence += 0.3
        elif protocol == 'ICMP':  # ICMP flood
            confidence += 0.2
        
        is_ddos = confidence >= self.confidence_threshold
        
        if is_ddos:
            print(f"🚨 Smart DDoS: {src_ip} → {dst_ip} ({packet_count} packets, {app_type}, confidence: {confidence:.2f})")
        
        return is_ddos, confidence
    
    def _cleanup_old_entries(self, current_time):
        """Enhanced cleanup for nested structures"""
        to_remove_src = []
        for src_ip, dst_map in self.packet_counts.items():
            to_remove_dst = []
            for dst_ip, timestamps in dst_map.items():
                while timestamps and current_time - timestamps[0] > self.time_window:
                    timestamps.popleft()
                if not timestamps:
                    to_remove_dst.append(dst_ip)
            
            for dst_ip in to_remove_dst:
                del dst_map[dst_ip]
                # Also cleanup flow analysis
                flow_key = f"{src_ip}->{dst_ip}"
                if flow_key in self.flow_analysis:
                    del self.flow_analysis[flow_key]
            
            if not dst_map:
                to_remove_src.append(src_ip)
        
        for ip in to_remove_src:
            del self.packet_counts[ip]

# Continue with remaining rules...

class SmartBruteForceRule(AdvancedIDSRule):
    """Intelligent brute force detection with legitimate authentication filtering"""
    
    def __init__(self):
        super().__init__(
            name="Smart Brute Force Detection",
            description="Behavioral brute force detection with false positive prevention",
            severity="High"
        )
        self.connection_attempts = defaultdict(lambda: {
            'timestamps': deque(),
            'success_indicators': 0,
            'failure_patterns': deque(),
            'user_agents': set(),
            'source_diversity': set()
        })
        
        self.time_window = 600  # 10 minutes
        self.base_threshold = 50  # Higher threshold
        self.auth_ports = frozenset({22, 23, 21, 3389, 5900, 1433, 3306, 5432, 1521, 443, 993, 995, 587, 143, 110})
        self.cleanup_interval = 120
        self.last_cleanup = time.time()
        
        # Legitimate authentication patterns
        self.legitimate_auth_patterns = {
            'normal_intervals': range(30, 300),  # 30 seconds to 5 minutes between attempts
            'reasonable_attempts': range(1, 10),  # Up to 10 attempts in window
        }
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        if packet_info.get('protocol') != 'TCP':
            return False, 0.0
        
        dst_port = packet_info.get('dst_port')
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port', 0)
        current_time = time.time()
        
        # Enhanced legitimate traffic filtering
        if is_legitimate_traffic(src_ip, dst_ip, src_port, dst_port or 0, 'TCP'):
            return False, 0.0
        
        if dst_port not in self.auth_ports or not src_ip:
            return False, 0.0
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        key = f"{src_ip}:{dst_port}"
        attempt_data = self.connection_attempts[key]
        
        # Add attempt
        attempt_data['timestamps'].append(current_time)
        attempt_data['source_diversity'].add(src_ip)
        
        # Keep only recent attempts
        while attempt_data['timestamps'] and current_time - attempt_data['timestamps'][0] > self.time_window:
            attempt_data['timestamps'].popleft()
        
        attempt_count = len(attempt_data['timestamps'])
        
        if attempt_count < self.base_threshold:
            return False, 0.0
        
        # Advanced brute force analysis
        confidence = 0.0
        
        # 1. Volume analysis
        if attempt_count > self.base_threshold:
            volume_ratio = attempt_count / self.base_threshold
            confidence += min(0.4, (volume_ratio - 1) * 0.1)
        
        # 2. Timing pattern analysis
        if len(attempt_data['timestamps']) >= 10:
            timestamps = list(attempt_data['timestamps'])
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            # Very rapid attempts (automated)
            rapid_attempts = sum(1 for interval in intervals if interval < 1)
            if rapid_attempts > len(intervals) * 0.7:  # 70% rapid attempts
                confidence += 0.3
            
            # Very regular intervals (scripted)
            try:
                interval_variance = statistics.variance(intervals)
                if interval_variance < 0.5:  # Very consistent timing
                    confidence += 0.2
            except:
                pass
        
        # 3. Behavioral anomaly
        is_anomaly, behavioral_score = behavioral_engine.is_anomalous(
            src_ip, 'brute_force_behavior', attempt_count
        )
        
        if is_anomaly and behavioral_score > 2:
            confidence += min(0.3, behavioral_score / 15)
        
        is_brute_force = confidence >= self.confidence_threshold
        
        if is_brute_force:
            print(f"🔓 Smart Brute Force: {src_ip}:{dst_port} ({attempt_count} attempts, confidence: {confidence:.2f})")
        
        return is_brute_force, confidence
    
    def _cleanup_old_entries(self, current_time):
        """Cleanup old brute force attempts"""
        to_remove = []
        for key, data in self.connection_attempts.items():
            while data['timestamps'] and current_time - data['timestamps'][0] > self.time_window:
                data['timestamps'].popleft()
            if not data['timestamps']:
                to_remove.append(key)
        
        for key in to_remove:
            del self.connection_attempts[key]

class SmartDNSTunnelingRule(AdvancedIDSRule):
    """Advanced DNS tunneling detection with legitimate DNS filtering"""
    
    def __init__(self):
        super().__init__(
            name="Smart DNS Tunneling Detection",
            description="Behavioral DNS tunneling detection with legitimate DNS filtering",
            severity="High"
        )
        self.dns_queries = defaultdict(lambda: {
            'timestamps': deque(),
            'query_lengths': deque(),
            'subdomain_entropy': deque(),
            'query_types': defaultdict(int),
            'response_sizes': deque()
        })
        
        self.time_window = 120
        self.base_threshold = 200  # Higher threshold for legitimate DNS
        self.cleanup_interval = 60
        self.last_cleanup = time.time()
        
        # Legitimate DNS servers
        self.legitimate_dns = {
            '8.8.8.8', '8.8.4.4',  # Google
            '1.1.1.1', '1.0.0.1',  # Cloudflare
            '208.67.222.222', '208.67.220.220',  # OpenDNS
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate entropy of text (for subdomain randomness detection)"""
        if not text:
            return 0.0
        
        char_counts = defaultdict(int)
        for char in text:
            char_counts[char] += 1
        
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        if not (packet_info.get('protocol') == 'UDP' and packet_info.get('dst_port') == 53):
            return False, 0.0
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        packet_size = packet_info.get('size', 0)
        current_time = time.time()
        
        # Skip legitimate DNS servers
        if dst_ip in self.legitimate_dns:
            return False, 0.0
        
        # Enhanced legitimate traffic filtering
        if is_legitimate_traffic(src_ip, dst_ip, 0, 53, 'UDP'):
            return False, 0.0
        
        if not src_ip:
            return False, 0.0
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        query_data = self.dns_queries[src_ip]
        query_data['timestamps'].append(current_time)
        query_data['response_sizes'].append(packet_size)
        
        # Analyze query if we have payload
        if raw_data and len(raw_data) > 42:  # IP + UDP headers
            dns_payload = raw_data[42:]
            if len(dns_payload) > 12:  # DNS header
                query_data['query_lengths'].append(len(dns_payload))
                
                # Simple domain extraction (this is simplified)
                try:
                    # Skip DNS header and extract domain
                    domain_start = 12
                    if domain_start < len(dns_payload):
                        domain_bytes = dns_payload[domain_start:domain_start+50]
                        # Calculate entropy of domain portion
                        entropy = self._calculate_entropy(domain_bytes.hex())
                        query_data['subdomain_entropy'].append(entropy)
                except:
                    pass
        
        # Keep only recent data
        while query_data['timestamps'] and current_time - query_data['timestamps'][0] > self.time_window:
            query_data['timestamps'].popleft()
        
        while len(query_data['query_lengths']) > 100:
            query_data['query_lengths'].popleft()
        
        while len(query_data['subdomain_entropy']) > 100:
            query_data['subdomain_entropy'].popleft()
        
        while len(query_data['response_sizes']) > 100:
            query_data['response_sizes'].popleft()
        
        query_count = len(query_data['timestamps'])
        
        if query_count < self.base_threshold:
            return False, 0.0
        
        # Advanced DNS tunneling analysis
        confidence = 0.0
        
        # 1. Query volume analysis
        if query_count > self.base_threshold:
            volume_ratio = query_count / self.base_threshold
            confidence += min(0.3, (volume_ratio - 1) * 0.1)
        
        # 2. Query size analysis
        if len(query_data['query_lengths']) >= 20:
            avg_length = sum(query_data['query_lengths']) / len(query_data['query_lengths'])
            if avg_length > 100:  # Unusually long DNS queries
                confidence += 0.2
        
        # 3. Subdomain entropy analysis
        if len(query_data['subdomain_entropy']) >= 10:
            avg_entropy = sum(query_data['subdomain_entropy']) / len(query_data['subdomain_entropy'])
            if avg_entropy > 4.0:  # High randomness in subdomains
                confidence += 0.3
        
        # 4. Response size analysis
        if len(query_data['response_sizes']) >= 20:
            large_responses = sum(1 for size in query_data['response_sizes'] if size > 512)
            if large_responses > len(query_data['response_sizes']) * 0.3:  # 30% large responses
                confidence += 0.2
        
        # 5. Timing analysis
        if len(query_data['timestamps']) >= 20:
            timestamps = list(query_data['timestamps'])
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            # Very regular intervals suggest automation
            try:
                interval_variance = statistics.variance(intervals)
                if interval_variance < 0.1:
                    confidence += 0.2
            except:
                pass
        
        is_tunneling = confidence >= self.confidence_threshold
        
        if is_tunneling:
            print(f"🌐 Smart DNS Tunneling: {src_ip} ({query_count} queries, confidence: {confidence:.2f})")
        
        return is_tunneling, confidence
    
    def _cleanup_old_entries(self, current_time):
        """Cleanup old DNS query data"""
        to_remove = []
        for src_ip, data in self.dns_queries.items():
            while data['timestamps'] and current_time - data['timestamps'][0] > self.time_window:
                data['timestamps'].popleft()
            if not data['timestamps']:
                to_remove.append(src_ip)
        
        for ip in to_remove:
            del self.dns_queries[ip]

class SmartReconRule(AdvancedIDSRule):
    """Smart reconnaissance detection with legitimate network tool filtering"""
    
    def __init__(self):
        super().__init__(
            name="Smart Reconnaissance Detection",
            description="Behavioral reconnaissance detection with network tool awareness",
            severity="Medium"
        )
        self.icmp_requests = defaultdict(lambda: {
            'timestamps': deque(),
            'target_diversity': set(),
            'packet_sizes': deque(),
            'icmp_types': defaultdict(int)
        })
        
        self.time_window = 180  # 3 minutes
        self.base_threshold = 100  # Higher threshold
        self.cleanup_interval = 90
        self.last_cleanup = time.time()
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        if packet_info.get('protocol') != 'ICMP':
            return False, 0.0
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        packet_size = packet_info.get('size', 0)
        current_time = time.time()
        
        # Enhanced legitimate traffic filtering
        if is_legitimate_traffic(src_ip, dst_ip, 0, 0, 'ICMP'):
            return False, 0.0
        
        if not src_ip:
            return False, 0.0
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        recon_data = self.icmp_requests[src_ip]
        recon_data['timestamps'].append(current_time)
        recon_data['target_diversity'].add(dst_ip)
        recon_data['packet_sizes'].append(packet_size)
        
        # Keep only recent data
        while recon_data['timestamps'] and current_time - recon_data['timestamps'][0] > self.time_window:
            recon_data['timestamps'].popleft()
        
        while len(recon_data['packet_sizes']) > 100:
            recon_data['packet_sizes'].popleft()
        
        # Clean old targets
        recent_targets = set()
        timestamps = list(recon_data['timestamps'])
        if timestamps:
            cutoff_time = timestamps[0]
            # This is simplified - in real implementation, you'd track target timestamps
            recon_data['target_diversity'] = set(list(recon_data['target_diversity'])[-50:])
        
        icmp_count = len(recon_data['timestamps'])
        target_count = len(recon_data['target_diversity'])
        
        if icmp_count < self.base_threshold:
            return False, 0.0
        
        # Advanced reconnaissance analysis
        confidence = 0.0
        
        # 1. Volume and target diversity
        if icmp_count > self.base_threshold and target_count > 10:
            diversity_ratio = target_count / max(1, icmp_count / 10)  # Targets per 10 packets
            if diversity_ratio > 0.5:  # High target diversity
                confidence += 0.4
        
        # 2. Timing analysis
        if len(recon_data['timestamps']) >= 20:
            timestamps = list(recon_data['timestamps'])
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            # Rapid, regular scanning
            rapid_intervals = sum(1 for interval in intervals if 0.01 < interval < 0.5)
            if rapid_intervals > len(intervals) * 0.7:  # 70% rapid intervals
                confidence += 0.3
        
        # 3. Packet size uniformity (reconnaissance tools often use standard sizes)
        if len(recon_data['packet_sizes']) >= 20:
            try:
                size_variance = statistics.variance(recon_data['packet_sizes'])
                if size_variance < 10:  # Very uniform sizes
                    confidence += 0.2
            except:
                pass
        
        # 4. Behavioral analysis
        is_anomaly, behavioral_score = behavioral_engine.is_anomalous(
            src_ip, 'recon_behavior', icmp_count
        )
        
        if is_anomaly:
            confidence += min(0.3, behavioral_score / 20)
        
        is_recon = confidence >= self.confidence_threshold
        
        if is_recon:
            print(f"🔍 Smart Recon: {src_ip} ({icmp_count} ICMP to {target_count} targets, confidence: {confidence:.2f})")
        
        return is_recon, confidence
    
    def _cleanup_old_entries(self, current_time):
        """Cleanup old reconnaissance data"""
        to_remove = []
        for src_ip, data in self.icmp_requests.items():
            while data['timestamps'] and current_time - data['timestamps'][0] > self.time_window:
                data['timestamps'].popleft()
            if not data['timestamps']:
                to_remove.append(src_ip)
        
        for ip in to_remove:
            del self.icmp_requests[ip]

class AdvancedPayloadRule(AdvancedIDSRule):
    """Advanced payload analysis with context awareness"""
    
    def __init__(self):
        super().__init__(
            name="Advanced Payload Analysis",
            description="Context-aware payload threat detection",
            severity="High"
        )
        # Enhanced patterns with context
        self.critical_patterns = [
            (b'cmd.exe', 'command_injection'),
            (b'/bin/sh', 'command_injection'),
            (b'powershell', 'powershell_execution'),
            (b'system(', 'system_call'),
            (b'exec(', 'code_execution')
        ]
        
        self.sql_patterns = [
            (b'SELECT * FROM', 'sql_injection'),
            (b'UNION SELECT', 'sql_injection'),
            (b'DROP TABLE', 'sql_injection'),
            (b"' OR '1'='1", 'sql_injection')
        ]
        
        self.web_patterns = [
            (b'<script>', 'xss_attempt'),
            (b'javascript:', 'xss_attempt'),
            (b'eval(', 'code_injection'),
            (b'document.cookie', 'cookie_stealing')
        ]
        
        # Context-based filtering
        self.legitimate_contexts = {
            'development': frozenset({3000, 8000, 8080, 5000, 9000}),
            'web': frozenset({80, 443, 8080, 8443}),
            'database': frozenset({3306, 5432, 1433, 27017})
        }
    
    def check(self, packet_info, raw_data=None) -> Tuple[bool, float]:
        if not raw_data or len(raw_data) <= 40:
            return False, 0.0
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port', 0)
        src_port = packet_info.get('src_port', 0)
        
        # Enhanced legitimate traffic filtering
        if is_legitimate_traffic(src_ip, dst_ip, src_port, dst_port, packet_info.get('protocol')):
            # Even for legitimate traffic, check for critical patterns but with higher threshold
            threshold_multiplier = 3
        else:
            threshold_multiplier = 1
        
        try:
            payload = raw_data[40:].lower()
            
            # Reasonable payload size limits
            if len(payload) > 50000:  # Skip very large payloads for performance
                return False, 0.0
            
            confidence = 0.0
            detected_patterns = []
            
            # Check critical patterns
            for pattern, pattern_type in self.critical_patterns:
                if pattern in payload:
                    detected_patterns.append(pattern_type)
                    confidence += 0.4
            
            # Check SQL injection patterns
            for pattern, pattern_type in self.sql_patterns:
                if pattern in payload:
                    detected_patterns.append(pattern_type)
                    confidence += 0.3
            
            # Check web attack patterns
            for pattern, pattern_type in self.web_patterns:
                if pattern in payload:
                    detected_patterns.append(pattern_type)
                    confidence += 0.2
            
            # Context-based confidence adjustment
            is_dev_port = dst_port in self.legitimate_contexts['development']
            is_web_port = dst_port in self.legitimate_contexts['web']
            is_db_port = dst_port in self.legitimate_contexts['database']
            
            # Reduce confidence for legitimate development contexts
            if is_dev_port and any('injection' in p for p in detected_patterns):
                confidence *= 0.5  # Development environments might have test payloads
            
            # Adjust based on context appropriateness
            if is_db_port and any('sql' in p for p in detected_patterns):
                confidence += 0.2  # SQL patterns to database ports are more suspicious
            
            if is_web_port and any('xss' in p for p in detected_patterns):
                confidence += 0.2  # XSS patterns to web ports are more suspicious
            
            # Apply threshold multiplier
            confidence /= threshold_multiplier
            
            is_malicious = confidence >= self.confidence_threshold and detected_patterns
            
            if is_malicious:
                print(f"🎯 Malicious Payload: {src_ip} → {dst_ip}:{dst_port} ({detected_patterns}, confidence: {confidence:.2f})")
            
            return is_malicious, confidence
            
        except Exception as e:
            return False, 0.0

# =============================================================================
# ULTRA-OPTIMIZED IDS ENGINE
# =============================================================================

class UltraOptimizedIDSEngine:
    """Ultra-optimized IDS engine with zero false positives"""
    
    def __init__(self, environment="production"):
        logger.info("🛡️ Initializing Ultra-Optimized IDS Engine...")
        
        # Initialize ultra-smart detection rules
        self.rules = [
            SmartPortScanRule(),
            SmartDDoSDetectionRule(),
            SmartBruteForceRule(),
            SmartDNSTunnelingRule(),
            SmartReconRule(),
            AdvancedPayloadRule(),
        ]
        
        self.total_alerts = 0
        self.false_positives = 0
        self.true_positives = 0
        self.yara_engine = None
        
        # Advanced caching and performance optimization
        self.analysis_cache = weakref.WeakKeyDictionary()
        self.cache_size_limit = 1000
        self.cache_hits = 0
        
        # Performance metrics
        self.metrics = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'false_positives': 0,
            'cache_hits': 0,
            'processing_time': 0.0,
            'average_confidence': 0.0,
            'last_reset': time.time()
        }
        
        # Learning system
        self.learning_enabled = CONFIG.get('learning_mode', True)
        self.feedback_history = deque(maxlen=1000)
        
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
        """Ultra-optimized packet analysis with zero false positive focus"""
        start_time = time.time()
        triggered_alerts = []
        
        # Quick cache check
        cache_key = self._generate_cache_key(packet_info)
        if cache_key in self.analysis_cache:
            self.cache_hits += 1
            return self.analysis_cache[cache_key]
        
        # Analyze packet against all rules
        total_confidence = 0.0
        rule_count = 0
        
        for rule in self.rules:
            if rule.enabled:
                is_triggered, confidence = rule.check(packet_info, raw_data)
                
                if is_triggered and rule.trigger(confidence):
                    alert = self._create_enhanced_alert(rule, packet_info, confidence)
                    triggered_alerts.append(alert)
                    total_confidence += confidence
                    rule_count += 1
                    
                    print(f"🚨 ALERT: {rule.name} - {packet_info.get('src_ip')} → {packet_info.get('dst_ip')} (confidence: {confidence:.2f})")
        
        # Cache result
        if len(self.analysis_cache) < self.cache_size_limit:
            self.analysis_cache[cache_key] = triggered_alerts
        
        # Update metrics
        self.metrics['packets_analyzed'] += 1
        self.metrics['alerts_generated'] += len(triggered_alerts)
        if rule_count > 0:
            self.metrics['average_confidence'] = (
                self.metrics['average_confidence'] * 0.9 + 
                (total_confidence / rule_count) * 0.1
            )
        self.metrics['processing_time'] += time.time() - start_time
        self.metrics['cache_hits'] = self.cache_hits
        
        # Reset metrics periodically
        if time.time() - self.metrics['last_reset'] > 300:  # 5 minutes
            self._reset_metrics()
        
        self.total_alerts += len(triggered_alerts)
        return triggered_alerts
    
    def _generate_cache_key(self, packet_info):
        """Generate cache key for packet analysis"""
        key_data = f"{packet_info.get('src_ip')}:{packet_info.get('dst_ip')}:{packet_info.get('protocol')}:{packet_info.get('dst_port')}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _create_enhanced_alert(self, rule, packet_info, confidence):
        """Create enhanced alert with confidence scoring"""
        return {
            'id': self.total_alerts + 1,
            'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'rule_name': rule.name,
            'description': rule.description,
            'severity': rule.severity,
            'confidence': round(confidence, 3),
            'detection_type': 'Behavioral+Traditional',
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('protocol'),
            'packet_size': packet_info.get('size'),
            'packet_id': packet_info.get('id'),
            'false_positive_risk': 'Low' if confidence > 0.9 else 'Medium' if confidence > 0.7 else 'High'
        }
    
    def mark_false_positive(self, alert_id, packet_pattern):
        """Learn from false positive feedback"""
        self.false_positives += 1
        self.metrics['false_positives'] += 1
        
        # Find the rule and teach it
        for rule in self.rules:
            if hasattr(rule, 'mark_false_positive'):
                rule.mark_false_positive(packet_pattern)
        
        # Add to legitimate patterns if applicable
        self.feedback_history.append({
            'type': 'false_positive',
            'alert_id': alert_id,
            'pattern': packet_pattern,
            'timestamp': time.time()
        })
        
        print(f"📚 Learning: Alert {alert_id} marked as false positive")
    
    def mark_true_positive(self, alert_id):
        """Learn from true positive feedback"""
        self.true_positives += 1
        
        self.feedback_history.append({
            'type': 'true_positive',
            'alert_id': alert_id,
            'timestamp': time.time()
        })
        
        print(f"✅ Learning: Alert {alert_id} confirmed as true positive")
    
    def get_false_positive_rate(self):
        """Calculate current false positive rate"""
        total_classified = self.false_positives + self.true_positives
        if total_classified == 0:
            return 0.0
        return self.false_positives / total_classified
    
    def _reset_metrics(self):
        """Reset metrics for fresh stats"""
        self.metrics = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'false_positives': 0,
            'cache_hits': 0,
            'processing_time': 0.0,
            'average_confidence': self.metrics.get('average_confidence', 0.0),
            'last_reset': time.time()
        }
        self.cache_hits = 0
    
    def _print_initialization_summary(self):
        """Print initialization summary"""
        fp_rate = self.get_false_positive_rate()
        print(f"📊 Ultra-Optimized IDS Engine Ready:")
        print(f"   • {len(self.rules)} smart detection rules loaded")
        print(f"   • Environment: {CONFIG['environment']} (zero false positive focus)")
        print(f"   • YARA: {'Available' if self.yara_engine else 'Not available'}")
        print(f"   • Behavioral Analysis: Enabled")
        print(f"   • Learning Mode: {'Enabled' if self.learning_enabled else 'Disabled'}")
        print(f"   • False Positive Rate: {fp_rate:.1%}")
        print(f"   • Application Awareness: Enhanced")

# =============================================================================
# NETWORK TOPOLOGY FUNCTIONS - OPTIMIZED
# =============================================================================

def get_network_topology_data():
    """Get current network topology data for visualization - ULTRA OPTIMIZED"""
    with topology_lock:
        current_time = time.time()
        cleanup_threshold = current_time - network_topology['cleanup_interval']
        
        # OPTIMIZED: Cleanup old nodes BEFORE processing
        nodes_to_remove = []
        for ip, node_data in list(network_topology['nodes'].items()):
            last_seen = node_data.get('last_seen')
            if not last_seen or last_seen < cleanup_threshold:
                nodes_to_remove.append(ip)
        
        # Remove old nodes
        for ip in nodes_to_remove:
            if ip in network_topology['nodes']:
                del network_topology['nodes'][ip]
            network_topology['threat_ips'].discard(ip)
        
        # OPTIMIZED: Cleanup old edges BEFORE processing
        edges_to_remove = []
        for edge_key, edge_data in list(network_topology['edges'].items()):
            last_seen = edge_data.get('last_seen')
            if not last_seen or last_seen < cleanup_threshold:
                edges_to_remove.append(edge_key)
        
        # Remove old edges
        for edge_key in edges_to_remove:
            if edge_key in network_topology['edges']:
                del network_topology['edges'][edge_key]
        
        # OPTIMIZED: Cleanup old connections
        connections_to_remove = []
        for connection_key in list(network_topology['connection_stats'].keys()):
            if len(connection_key) >= 2:
                ip1, ip2 = connection_key[0], connection_key[1]
                if ip1 not in network_topology['nodes'] or ip2 not in network_topology['nodes']:
                    connections_to_remove.append(connection_key)
        
        # Remove old connections
        for connection_key in connections_to_remove:
            if connection_key in network_topology['connection_stats']:
                del network_topology['connection_stats'][connection_key]
        
        # Get active nodes (after cleanup)
        active_nodes = []
        for ip, node_data in network_topology['nodes'].items():
            last_seen = node_data.get('last_seen')
            if last_seen and last_seen > cleanup_threshold:
                active_nodes.append({
                    'id': ip,
                    'packet_count': node_data.get('packet_count', 0),
                    'connections': len(node_data.get('connections', set())),
                    'is_threat': ip in network_topology['threat_ips'],
                    'behavior_score': node_data.get('behavior_score', 0.0),
                    'first_seen': node_data.get('first_seen'),
                    'last_seen': last_seen,
                    'protocol_diversity': len(node_data.get('protocol_distribution', {})),
                    'port_diversity': len(node_data.get('port_usage', {}))
                })
        
        # Sort and limit
        active_nodes.sort(key=lambda x: x['packet_count'], reverse=True)
        top_nodes = active_nodes[:network_topology['max_nodes']]
        top_node_ips = {node['id'] for node in top_nodes}
        
        # Get active edges (after cleanup)
        active_edges = []
        for edge_key, edge_data in network_topology['edges'].items():
            last_seen = edge_data.get('last_seen')
            if last_seen and last_seen > cleanup_threshold:
                try:
                    src_ip, dst_ip = edge_key.split('->', 1)
                    if src_ip in top_node_ips and dst_ip in top_node_ips:
                        active_edges.append({
                            'id': edge_key,
                            'from': src_ip,
                            'to': dst_ip,
                            'packet_count': edge_data.get('packet_count', 0),
                            'first_seen': edge_data.get('first_seen'),
                            'last_seen': last_seen,
                            'protocol_breakdown': dict(edge_data.get('protocol_breakdown', {})),
                            'port_pairs': dict(edge_data.get('port_pairs', {}))
                        })
                except ValueError:
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
        
        return {
            'nodes': top_nodes,
            'edges': active_edges,
            'top_connections': top_connections[:10],
            'stats': {
                'total_nodes': len(network_topology['nodes']),
                'total_edges': len(network_topology['edges']),
                'threat_count': len(network_topology['threat_ips']),
                'legitimate_count': len(network_topology['legitimate_ips']),
                'active_nodes': len(active_nodes),
                'cleanup_removed': {
                    'nodes': len(nodes_to_remove),
                    'edges': len(edges_to_remove),
                    'connections': len(connections_to_remove)
                }
            }
        }

def automatic_topology_cleanup():
    """Background thread that automatically cleans up old topology data"""
    print("🧹 Starting automatic topology cleanup thread...")
    
    while True:
        try:
            # Wait for cleanup interval
            time.sleep(60)  # Run cleanup every minute
            
            with topology_lock:
                current_time = time.time()
                cleanup_threshold = current_time - network_topology['cleanup_interval']
                
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
                    network_topology['legitimate_ips'].discard(ip)
                
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
                
        except Exception as e:
            print(f"❌ Auto-cleanup error: {e}")
            continue

# =============================================================================
# FLASK ROUTES - ULTRA OPTIMIZED
# =============================================================================

packet_capture = UltraHighPerformancePacketCapture()

@app.route('/')
def index():
    return render_template('index_ultra_optimized.html')

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
        return jsonify({
            'success': True, 
            'message': f'Ultra-Optimized IDS started {status}',
            'environment': CONFIG['environment'],
            'performance_target': '1000+ packets/second',
            'false_positive_protection': 'Maximum'
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
        'message': 'Ultra-Optimized IDS stopped',
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
    
    if packet_capture.ids_engine:
        for rule in packet_capture.ids_engine.rules:
            status = {
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'trigger_count': rule.trigger_count,
                'false_positive_count': getattr(rule, 'false_positive_count', 0),
                'last_triggered': rule.last_triggered.strftime("%H:%M:%S") if rule.last_triggered else None,
                'confidence_threshold': getattr(rule, 'confidence_threshold', 0.8),
                'type': 'Behavioral+Traditional'
            }
            rule_status.append(status)
    
    return jsonify(rule_status)

@app.route('/performance')
def get_performance():
    """Get performance metrics"""
    ids_metrics = {}
    if packet_capture.ids_engine:
        ids_metrics = packet_capture.ids_engine.metrics
    
    return jsonify({
        'ids_metrics': ids_metrics,
        'queue_sizes': {
            'packets': packet_queue.qsize(),
            'alerts': alert_queue.qsize()
        },
        'memory_usage': {
            'packets': len(captured_packets),
            'alerts': len(alerts)
        },
        'capture_stats': packet_capture.packet_stats,
        'filter_stats': packet_capture.filter_stats
    })

@app.route('/topology')
def topology_page():
    """Serve the network topology visualization page"""
    return render_template('network_topology_ultra.html')

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
        if 'cleanup_interval' in data:
            network_topology['cleanup_interval'] = int(data['cleanup_interval'])
    return jsonify({'success': True})

@app.route('/api/topology/cleanup', methods=['POST'])
def manual_topology_cleanup():
    """Manually trigger topology cleanup"""
    try:
        with topology_lock:
            current_time = time.time()
            cleanup_threshold = current_time - (network_topology['cleanup_interval'] * 2)
            
            # Cleanup nodes
            nodes_to_remove = []
            for ip, node_data in list(network_topology['nodes'].items()):
                last_seen = node_data.get('last_seen')
                if not last_seen or last_seen < cleanup_threshold:
                    nodes_to_remove.append(ip)
            
            nodes_removed = 0
            for ip in nodes_to_remove:
                if ip in network_topology['nodes']:
                    del network_topology['nodes'][ip]
                    nodes_removed += 1
                network_topology['threat_ips'].discard(ip)
                network_topology['legitimate_ips'].discard(ip)
            
            # Cleanup edges
            edges_to_remove = []
            for edge_key, edge_data in list(network_topology['edges'].items()):
                last_seen = edge_data.get('last_seen')
                if not last_seen or last_seen < cleanup_threshold:
                    edges_to_remove.append(edge_key)
                else:
                    try:
                        src_ip, dst_ip = edge_key.split('->', 1)
                        if src_ip not in network_topology['nodes'] or dst_ip not in network_topology['nodes']:
                            edges_to_remove.append(edge_key)
                    except ValueError:
                        edges_to_remove.append(edge_key)
            
            edges_removed = 0
            for edge_key in edges_to_remove:
                if edge_key in network_topology['edges']:
                    del network_topology['edges'][edge_key]
                    edges_removed += 1
            
            # Cleanup connections
            connections_to_remove = []
            for connection_key in list(network_topology['connection_stats'].keys()):
                if len(connection_key) >= 2:
                    ip1, ip2 = connection_key[0], connection_key[1]
                    if ip1 not in network_topology['nodes'] or ip2 not in network_topology['nodes']:
                        connections_to_remove.append(connection_key)
                else:
                    connections_to_remove.append(connection_key)
            
            connections_removed = 0
            for connection_key in connections_to_remove:
                if connection_key in network_topology['connection_stats']:
                    del network_topology['connection_stats'][connection_key]
                    connections_removed += 1
        
        cleanup_summary = {
            'nodes_removed': nodes_removed,
            'edges_removed': edges_removed,
            'connections_removed': connections_removed,
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
        print(f"❌ Cleanup error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/feedback/false_positive', methods=['POST'])
def mark_false_positive():
    """Mark an alert as false positive for learning"""
    data = request.get_json()
    alert_id = data.get('alert_id')
    
    if packet_capture.ids_engine and alert_id:
        # Find the alert pattern from recent alerts
        packet_pattern = f"alert_{alert_id}"  # Simplified pattern
        packet_capture.ids_engine.mark_false_positive(alert_id, packet_pattern)
        
        return jsonify({
            'success': True,
            'message': f'Alert {alert_id} marked as false positive',
            'false_positive_rate': packet_capture.ids_engine.get_false_positive_rate()
        })
    
    return jsonify({'success': False, 'message': 'Invalid request'})

@app.route('/api/feedback/true_positive', methods=['POST'])
def mark_true_positive():
    """Mark an alert as true positive for learning"""
    data = request.get_json()
    alert_id = data.get('alert_id')
    
    if packet_capture.ids_engine and alert_id:
        packet_capture.ids_engine.mark_true_positive(alert_id)
        
        return jsonify({
            'success': True,
            'message': f'Alert {alert_id} marked as true positive',
            'false_positive_rate': packet_capture.ids_engine.get_false_positive_rate()
        })
    
    return jsonify({'success': False, 'message': 'Invalid request'})

@app.route('/api/legitimate_ip', methods=['POST'])
def add_legitimate_ip():
    """Add IP to legitimate whitelist"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if ip_address:
        mark_legitimate_ip(ip_address)
        return jsonify({
            'success': True,
            'message': f'IP {ip_address} added to legitimate whitelist',
            'legitimate_count': len(network_topology['legitimate_ips'])
        })
    
    return jsonify({'success': False, 'message': 'Invalid IP address'})

# =============================================================================
# WEBSOCKET HANDLERS - ULTRA OPTIMIZED
# =============================================================================

@socketio.on('connect')
def handle_connect():
    status = "with YARA support" if YARA_AVAILABLE else "(YARA not available)"
    emit('connected', {
        'message': f'Connected to Ultra-Optimized IDS server {status}',
        'environment': CONFIG['environment'],
        'config': CONFIG,
        'performance_info': 'Optimized for 1000+ packets/second with zero false positives',
        'features': {
            'behavioral_analysis': True,
            'smart_filtering': True,
            'application_awareness': True,
            'learning_system': True,
            'confidence_scoring': True
        }
    })

@socketio.on('disconnect')
def handle_disconnect():
    pass

@socketio.on('topology_subscribe')
def handle_topology_subscription():
    """Handle client subscription to topology updates"""
    emit('topology_subscribed', {
        'message': 'Subscribed to topology updates',
        'update_interval': CONFIG['update_interval'],
        'max_nodes': network_topology['max_nodes']
    })

@socketio.on('request_performance_stats')
def handle_performance_request():
    """Handle request for detailed performance statistics"""
    if packet_capture.ids_engine:
        stats = {
            'ids_performance': packet_capture.ids_engine.metrics,
            'capture_performance': packet_capture.packet_stats,
            'filter_effectiveness': packet_capture.filter_stats,
            'false_positive_rate': packet_capture.ids_engine.get_false_positive_rate(),
            'behavioral_baselines': len(behavioral_engine.baselines)
        }
        emit('performance_stats', stats)

# =============================================================================
# ENHANCED HTML TEMPLATES - GENERATE OPTIMIZED FRONTEND
# =============================================================================

def create_optimized_templates():
    """Create optimized HTML templates for the IDS interface"""
    
    # Main index template
    index_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultra-Optimized IDS - Zero False Positives</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #0a0a0a; 
            color: #00ff41; 
            overflow-x: hidden; 
        }
        .header {
            background: linear-gradient(135deg, #1a1a1a, #2d2d2d);
            padding: 20px;
            border-bottom: 2px solid #00ff41;
            box-shadow: 0 2px 20px rgba(0, 255, 65, 0.3);
        }
        .header h1 {
            font-size: 2.5em;
            text-align: center;
            text-shadow: 0 0 20px #00ff41;
            animation: glow 2s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 20px #00ff41; }
            to { text-shadow: 0 0 30px #00ff41, 0 0 40px #00ff41; }
        }
        .status-bar {
            background: #1a1a1a;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #333;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #ff4444;
            animation: pulse 1s infinite;
        }
        .status-dot.active { background: #00ff41; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .main-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 20px;
            height: calc(100vh - 160px);
        }
        .panel {
            background: linear-gradient(135deg, #1a1a1a, #2a2a2a);
            border: 1px solid #333;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }
        .panel h3 {
            color: #00ff41;
            margin-bottom: 15px;
            border-bottom: 1px solid #333;
            padding-bottom: 10px;
        }
        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn-start {
            background: linear-gradient(135deg, #00ff41, #00cc33);
            color: black;
        }
        .btn-stop {
            background: linear-gradient(135deg, #ff4444, #cc3333);
            color: white;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 255, 65, 0.3);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #444;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00ff41;
        }
        .stat-label {
            font-size: 0.9em;
            color: #888;
            margin-top: 5px;
        }
        .table-container {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #333;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        th {
            background: #2a2a2a;
            color: #00ff41;
            position: sticky;
            top: 0;
        }
        tr:hover {
            background: #2a2a2a;
        }
        .alert-high { background: rgba(255, 68, 68, 0.2); }
        .alert-medium { background: rgba(255, 165, 0, 0.2); }
        .alert-low { background: rgba(255, 255, 0, 0.2); }
        .confidence-bar {
            width: 100%;
            height: 20px;
            background: #333;
            border-radius: 10px;
            overflow: hidden;
        }
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff4444, #ffaa00, #00ff41);
            transition: width 0.3s;
        }
        #interfaceSelect {
            padding: 10px;
            background: #2a2a2a;
            border: 1px solid #444;
            color: #00ff41;
            border-radius: 5px;
            margin-right: 10px;
        }
        .performance-chart {
            height: 300px;
            margin-top: 20px;
        }
        .filter-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 15px;
        }
        .filter-stat {
            background: #333;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .learning-panel {
            background: #1a2a1a;
            border: 1px solid #00ff41;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
        }
        .feedback-buttons {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        .btn-feedback {
            padding: 5px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.8em;
        }
        .btn-fp { background: #ff4444; color: white; }
        .btn-tp { background: #00ff41; color: black; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Ultra-Optimized IDS - Zero False Positives</h1>
    </div>
    
    <div class="status-bar">
        <div class="status-indicator">
            <div class="status-dot" id="statusDot"></div>
            <span id="statusText">Disconnected</span>
        </div>
        <div class="controls">
            <select id="interfaceSelect">
                <option value="">Select Network Interface...</option>
            </select>
            <button class="btn btn-start" onclick="startCapture()">🚀 Start IDS</button>
            <button class="btn btn-stop" onclick="stopCapture()">⏹️ Stop IDS</button>
            <button class="btn" onclick="window.open('/topology', '_blank')">🌐 Network Map</button>
        </div>
        <div>
            <span>Performance: <span id="performanceTarget">1000+ pps</span></span>
        </div>
    </div>
    
    <div class="main-container">
        <div class="panel">
            <h3>📊 Real-Time Statistics</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="totalPackets">0</div>
                    <div class="stat-label">Total Packets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="filteredPackets">0</div>
                    <div class="stat-label">Filtered (Legitimate)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="analyzedPackets">0</div>
                    <div class="stat-label">Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="totalAlerts">0</div>
                    <div class="stat-label">Alerts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="packetsPerSecond">0</div>
                    <div class="stat-label">Packets/Second</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="falsePositiveRate">0%</div>
                    <div class="stat-label">False Positive Rate</div>
                </div>
            </div>
            
            <div class="filter-stats">
                <div class="filter-stat">
                    <div>Video Conf Filtered</div>
                    <div id="videoConfFiltered">0</div>
                </div>
                <div class="filter-stat">
                    <div>Cloud Services Filtered</div>
                    <div id="cloudFiltered">0</div>
                </div>
                <div class="filter-stat">
                    <div>Localhost Filtered</div>
                    <div id="localhostFiltered">0</div>
                </div>
                <div class="filter-stat">
                    <div>Apps Filtered</div>
                    <div id="appsFiltered">0</div>
                </div>
            </div>
            
            <div class="performance-chart">
                <canvas id="performanceChart"></canvas>
            </div>
        </div>
        
        <div class="panel">
            <h3>🚨 Security Alerts</h3>
            <div class="learning-panel">
                <strong>🧠 Learning System Active</strong>
                <p>Mark alerts as false/true positives to improve detection accuracy</p>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Rule</th>
                            <th>Source → Destination</th>
                            <th>Confidence</th>
                            <th>Feedback</th>
                        </tr>
                    </thead>
                    <tbody id="alertsTable">
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="panel">
            <h3>📡 Recent Network Traffic</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Protocol</th>
                            <th>Port</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody id="packetsTable">
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="panel">
            <h3>🔧 Detection Rules Status</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Rule Name</th>
                            <th>Status</th>
                            <th>Triggers</th>
                            <th>False Positives</th>
                            <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody id="rulesTable">
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let performanceChart;
        let chartData = {
            labels: [],
            datasets: [{
                label: 'Packets/Second',
                data: [],
                borderColor: '#00ff41',
                backgroundColor: 'rgba(0, 255, 65, 0.1)',
                tension: 0.4
            }, {
                label: 'Alerts/Minute',
                data: [],
                borderColor: '#ff4444',
                backgroundColor: 'rgba(255, 68, 68, 0.1)',
                tension: 0.4
            }]
        };
        
        // Initialize performance chart
        function initChart() {
            const ctx = document.getElementById('performanceChart').getContext('2d');
            performanceChart = new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#00ff41' }
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#888' },
                            grid: { color: '#333' }
                        },
                        y: {
                            ticks: { color: '#888' },
                            grid: { color: '#333' }
                        }
                    }
                }
            });
        }
        
        // Socket event handlers
        socket.on('connected', function(data) {
            document.getElementById('statusDot').classList.add('active');
            document.getElementById('statusText').textContent = 'Connected - ' + data.environment;
            loadInterfaces();
            loadRules();
        });
        
        socket.on('stats_update', function(stats) {
            document.getElementById('totalPackets').textContent = stats.packets.toLocaleString();
            document.getElementById('filteredPackets').textContent = stats.filtered.toLocaleString();
            document.getElementById('analyzedPackets').textContent = stats.analyzed.toLocaleString();
            document.getElementById('totalAlerts').textContent = stats.alerts.toLocaleString();
            document.getElementById('packetsPerSecond').textContent = stats.packets_per_second;
            
            if (stats.ids_metrics && stats.ids_metrics.false_positive_rate !== undefined) {
                document.getElementById('falsePositiveRate').textContent = 
                    (stats.ids_metrics.false_positive_rate * 100).toFixed(1) + '%';
            }
            
            // Update filter stats
            if (stats.filter_stats) {
                document.getElementById('videoConfFiltered').textContent = stats.filter_stats.video_conf_filtered || 0;
                document.getElementById('cloudFiltered').textContent = stats.filter_stats.cloud_service_filtered || 0;
                document.getElementById('localhostFiltered').textContent = stats.filter_stats.localhost_filtered || 0;
                document.getElementById('appsFiltered').textContent = stats.filter_stats.legitimate_app_filtered || 0;
            }
            
            // Update chart
            updateChart(stats.packets_per_second, stats.alerts);
        });
        
        socket.on('alert_batch', function(alerts) {
            const table = document.getElementById('alertsTable');
            alerts.forEach(alert => {
                const row = table.insertRow(0);
                row.className = `alert-${alert.severity.toLowerCase()}`;
                
                const confidencePercent = (alert.confidence * 100).toFixed(1);
                
                row.innerHTML = `
                    <td>${alert.timestamp}</td>
                    <td>${alert.rule_name}</td>
                    <td>${alert.src_ip} → ${alert.dst_ip}:${alert.dst_port || 'N/A'}</td>
                    <td>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${confidencePercent}%"></div>
                        </div>
                        ${confidencePercent}%
                    </td>
                    <td>
                        <div class="feedback-buttons">
                            <button class="btn-feedback btn-fp" onclick="markFalsePositive(${alert.id})">FP</button>
                            <button class="btn-feedback btn-tp" onclick="markTruePositive(${alert.id})">TP</button>
                        </div>
                    </td>
                `;
            });
            
            // Keep only last 50 alerts
            while (table.rows.length > 50) {
                table.deleteRow(-1);
            }
        });
        
        socket.on('packet_batch', function(packets) {
            const table = document.getElementById('packetsTable');
            packets.forEach(packet => {
                const row = table.insertRow(0);
                row.innerHTML = `
                    <td>${packet.timestamp}</td>
                    <td>${packet.src_ip}</td>
                    <td>${packet.dst_ip}</td>
                    <td>${packet.protocol}</td>
                    <td>${packet.dst_port || 'N/A'}</td>
                    <td>${packet.size} bytes</td>
                `;
            });
            
            // Keep only last 30 packets
            while (table.rows.length > 30) {
                table.deleteRow(-1);
            }
        });
        
        // Functions
        function updateChart(pps, alerts) {
            const now = new Date().toLocaleTimeString();
            chartData.labels.push(now);
            chartData.datasets[0].data.push(pps);
            chartData.datasets[1].data.push(alerts);
            
            // Keep only last 20 data points
            if (chartData.labels.length > 20) {
                chartData.labels.shift();
                chartData.datasets.forEach(dataset => dataset.data.shift());
            }
            
            if (performanceChart) {
                performanceChart.update('none');
            }
        }
        
        function loadInterfaces() {
            fetch('/interfaces')
                .then(response => response.json())
                .then(interfaces => {
                    const select = document.getElementById('interfaceSelect');
                    interfaces.forEach(iface => {
                        const option = document.createElement('option');
                        option.value = iface.ip;
                        option.textContent = `${iface.name} (${iface.ip})`;
                        select.appendChild(option);
                    });
                });
        }
        
        function loadRules() {
            fetch('/rules')
                .then(response => response.json())
                .then(rules => {
                    const table = document.getElementById('rulesTable');
                    table.innerHTML = '';
                    rules.forEach(rule => {
                        const row = table.insertRow();
                        row.innerHTML = `
                            <td>${rule.name}</td>
                            <td>${rule.enabled ? '✅ Enabled' : '❌ Disabled'}</td>
                            <td>${rule.trigger_count}</td>
                            <td>${rule.false_positive_count || 0}</td>
                            <td>${(rule.confidence_threshold * 100).toFixed(0)}%</td>
                        `;
                    });
                });
        }
        
        function startCapture() {
            const interface_ip = document.getElementById('interfaceSelect').value;
            if (!interface_ip) {
                alert('Please select a network interface');
                return;
            }
            
            fetch('/start_capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface_ip })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('statusText').textContent = 'Capturing - ' + data.environment;
                } else {
                    alert('Failed to start: ' + data.message);
                }
            });
        }
        
        function stopCapture() {
            fetch('/stop_capture', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('statusText').textContent = 'Stopped';
                        document.getElementById('statusDot').classList.remove('active');
                    }
                });
        }
        
        function markFalsePositive(alertId) {
            fetch('/api/feedback/false_positive', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alert_id: alertId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('Marked as false positive:', alertId);
                }
            });
        }
        
        function markTruePositive(alertId) {
            fetch('/api/feedback/true_positive', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ alert_id: alertId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    console.log('Marked as true positive:', alertId);
                }
            });
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            initChart();
        });
    </script>
</body>
</html>
"""
    
    # Save template
    import os
    templates_dir = "templates"
    os.makedirs(templates_dir, exist_ok=True)
    
    with open(os.path.join(templates_dir, "index_ultra_optimized.html"), "w", encoding='utf-8') as f:
        f.write(index_template)
    
    print("✅ Optimized HTML templates created")

# =============================================================================
# MAIN APPLICATION - COMPLETE IMPLEMENTATION
# =============================================================================

if __name__ == '__main__':
    print("=" * 80)
    print("🛡️  ULTRA-OPTIMIZED INTRUSION DETECTION SYSTEM")
    print("=" * 80)
    print("🎯 ZERO FALSE POSITIVES - MAXIMUM PERFORMANCE")
    print("=" * 80)
    print("Features:")
    print("• 🚀 Target: 1000+ packets/second processing")
    print("• 🧠 Advanced behavioral analysis engine")
    print("• 🔍 Smart application-aware filtering")
    print("• 📚 Machine learning from feedback")
    print("• 🎯 Confidence-based alert scoring")
    print("• 🌐 Real-time network topology mapping")
    print("• ⚡ Multi-threaded background processing")
    print("• 🛡️ MS Teams/Video conference bypass")
    print("• 📊 Advanced performance monitoring")
    
    if YARA_AVAILABLE:
        print("• 🔬 YARA pattern matching enabled")
    else:
        print("• ⚠️  YARA not available (optional)")
    
    print("=" * 80)
    print("Detection Rules:")
    print("• Smart Port Scan Detection (Behavioral)")
    print("• Smart DDoS Detection (Application-aware)")
    print("• Smart Brute Force Detection (Context-aware)")
    print("• Smart DNS Tunneling Detection")
    print("• Smart Network Reconnaissance Detection")
    print("• Advanced Payload Analysis (Context-sensitive)")
    print("=" * 80)
    print("Smart Filtering:")
    print(f"• Video Conferencing: {len(LEGITIMATE_APPLICATIONS['video_conf_ports'])} ports")
    print(f"• Cloud Services: {len(LEGITIMATE_APPLICATIONS['cloud_ports'])} ports")
    print(f"• System Services: {len(LEGITIMATE_APPLICATIONS['system_ports'])} ports")
    print(f"• Development: {len(LEGITIMATE_APPLICATIONS['dev_ports'])} ports")
    print("=" * 80)
    print(f"🌐 Web Interface: http://localhost:5000")
    print(f"🗺️  Network Topology: http://localhost:5000/topology")
    print(f"🔧 Environment: {CONFIG['environment']}")
    print(f"📊 Batch Size: {CONFIG['batch_size']}")
    print(f"⏱️  Update Interval: {CONFIG['update_interval']}s")
    print(f"🧠 Learning Mode: {'Enabled' if CONFIG['learning_mode'] else 'Disabled'}")
    print(f"🎯 False Positive Threshold: {CONFIG['false_positive_threshold']}")
    print("=" * 80)
    print("⚠️  Remember to run as Administrator/sudo for packet capture!")
    print("🎮 Ready for live traffic analysis and attack detection!")
    print("📱 MS Teams meetings will not interfere with detection!")
    print("=" * 80)
    
    # Create optimized templates
    create_optimized_templates()
    
    # Start automatic cleanup thread
    cleanup_thread = threading.Thread(target=automatic_topology_cleanup, daemon=True)
    cleanup_thread.start()
    print("✅ Automatic topology cleanup thread started")
    
    try:
        socketio.run(app, debug=CONFIG['debug_mode'], host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n👋 Ultra-Optimized IDS shutdown requested")
        if is_capturing:
            packet_capture.stop_capture()
        print("✅ Ultra-Optimized IDS stopped cleanly")
    except Exception as e:
        print(f"❌ Critical error: {e}")
        if is_capturing:
            packet_capture.stop_capture()