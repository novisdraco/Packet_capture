#!/usr/bin/env python3
"""
Web-based Packet Capture Application
A Flask web interface for capturing and viewing network packets
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet_capture_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
capture_thread = None
is_capturing = False
captured_packets = []
max_packets = 1000  # Limit stored packets to prevent memory issues

class PacketCapture:
    def __init__(self):
        self.conn = None
        self.is_running = False
        
    def get_network_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        for interface_name, addresses in psutil.net_if_addrs().items():
            for addr in addresses:
                if addr.family == socket.AF_INET:  # IPv4
                    interfaces.append({
                        'name': interface_name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
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
        """Capture packets and emit to web interface"""
        global captured_packets, is_capturing
        packet_count = 0
        
        while self.is_running:
            try:
                raw_data, addr = self.conn.recvfrom(65535)
                packet_count += 1
                
                # Parse packet
                packet_info = self.parse_packet(raw_data, packet_count)
                
                # Store packet (limit storage)
                captured_packets.append(packet_info)
                if len(captured_packets) > max_packets:
                    captured_packets.pop(0)
                
                # Emit to web interface
                socketio.emit('new_packet', packet_info)
                
            except Exception as e:
                if self.is_running:  # Only emit error if we're supposed to be running
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

# Initialize packet capture
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
    global capture_thread, is_capturing, captured_packets
    
    data = request.get_json()
    interface_ip = data.get('interface_ip')
    
    if is_capturing:
        return jsonify({'success': False, 'message': 'Capture already running'})
    
    # Clear previous packets
    captured_packets = []
    
    # Start capture
    result = packet_capture.start_capture(interface_ip)
    if result is True:
        is_capturing = True
        capture_thread = threading.Thread(target=packet_capture.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        return jsonify({'success': True, 'message': 'Capture started'})
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
    return jsonify({'success': True, 'message': 'Capture stopped'})

@app.route('/packets')
def get_packets():
    """Get captured packets"""
    return jsonify(captured_packets)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to packet capture server'})
    # Send existing packets to new client
    for packet in captured_packets[-50:]:  # Send last 50 packets
        emit('new_packet', packet)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass

if __name__ == '__main__':
    print("Starting Packet Capture Web Interface...")
    print("Access the interface at: http://localhost:5000")
    print("Remember to run as Administrator on Windows!")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)