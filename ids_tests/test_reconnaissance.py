#!/usr/bin/env python3
"""
Network Reconnaissance Detection Test - Working Version
Targets external IPs and generates proper ICMP traffic to trigger detection
ONLY USE ON YOUR OWN SYSTEM FOR TESTING
"""

import subprocess
import threading
import time
import sys
import platform
import socket
import struct
import random

class ReconnaissanceTest:
    def __init__(self):
        # External target options (bypass localhost filtering)
        self.target_options = [
            "8.8.8.8",          # Google DNS
            "1.1.1.1",          # Cloudflare DNS
            "208.67.222.222",   # OpenDNS
            "192.168.1.1",      # Common router IP
            "10.0.0.1",         # Private network gateway
            "172.16.0.1"        # Private network
        ]
        
        self.selected_targets = []
        self.ping_count = 0
        self.successful_pings = 0
        self.failed_pings = 0
        self.lock = threading.Lock()
        
        # Detect OS for ping command
        self.is_windows = platform.system().lower() == "windows"
        self.ping_cmd = self.get_ping_command()
    
    def select_targets(self):
        """Select reachable targets for reconnaissance"""
        print("🎯 Selecting targets for reconnaissance test...")
        
        for target in self.target_options:
            if self.test_reachability(target):
                self.selected_targets.append(target)
                print(f"✅ Target selected: {target}")
                if len(self.selected_targets) >= 3:  # Use up to 3 targets
                    break
        
        if not self.selected_targets:
            # Fallback to external DNS servers (always work for ICMP)
            self.selected_targets = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            print("⚠️  Using fallback external DNS servers")
        
        print(f"🎯 Final targets: {', '.join(self.selected_targets)}")
        return True
    
    def test_reachability(self, target_ip):
        """Test if target is reachable"""
        try:
            cmd = self.ping_cmd + [target_ip]
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            return True  # Even failures are fine - we just need to generate ICMP
        except:
            return True  # Always return True - we want to try pinging anyway
    
    def get_ping_command(self):
        """Get appropriate ping command for OS"""
        if self.is_windows:
            return ["ping", "-n", "1", "-w", "1000"]  # Windows: -n count, -w timeout
        else:
            return ["ping", "-c", "1", "-W", "1"]     # Linux/Mac: -c count, -W timeout
    
    def ping_host(self, target_ip):
        """Ping a single host"""
        try:
            cmd = self.ping_cmd + [target_ip]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                timeout=2,
                text=True
            )
            
            with self.lock:
                self.ping_count += 1
                
                if result.returncode == 0:
                    self.successful_pings += 1
                    print(f"✅ PING {self.ping_count}: {target_ip} - SUCCESS")
                else:
                    self.failed_pings += 1
                    print(f"❌ PING {self.ping_count}: {target_ip} - FAILED")
                
        except subprocess.TimeoutExpired:
            with self.lock:
                self.failed_pings += 1
                self.ping_count += 1
            print(f"⏰ PING {self.ping_count}: {target_ip} - TIMEOUT")
        except Exception as e:
            with self.lock:
                self.failed_pings += 1
                self.ping_count += 1
            print(f"❌ PING {self.ping_count}: {target_ip} - ERROR")
    
    def create_raw_icmp_packet(self):
        """Create a raw ICMP echo request packet"""
        # ICMP Header: type (8), code (0), checksum (0), id, sequence
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = random.randint(1, 65535)
        icmp_sequence = random.randint(1, 65535)
        
        # Payload
        payload = b"RECON_TEST_" + b"A" * 32
        
        # Pack header (checksum will be calculated later)
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)
        
        # Calculate checksum
        packet = icmp_header + payload
        icmp_checksum = self.calculate_checksum(packet)
        
        # Repack with correct checksum
        icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence)
        
        return icmp_header + payload
    
    def calculate_checksum(self, data):
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        
        return ~checksum & 0xFFFF
    
    def send_raw_icmp(self, target_ip):
        """Send raw ICMP packet"""
        try:
            # Create raw socket (requires admin privileges)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(1)
            
            # Create and send ICMP packet
            icmp_packet = self.create_raw_icmp_packet()
            sock.sendto(icmp_packet, (target_ip, 0))
            
            with self.lock:
                self.ping_count += 1
            
            print(f"📡 Raw ICMP {self.ping_count}: {target_ip} - SENT")
            sock.close()
            
        except PermissionError:
            # Fall back to regular ping
            self.ping_host(target_ip)
        except Exception as e:
            with self.lock:
                self.ping_count += 1
            print(f"❌ Raw ICMP {self.ping_count}: {target_ip} - ERROR")
    
    def icmp_flood_test(self, num_pings=60):
        """Generate ICMP flood to trigger reconnaissance detection"""
        if not self.select_targets():
            return
        
        print("=" * 60)
        print("📡 ICMP RECONNAISSANCE TEST")
        print("=" * 60)
        print(f"Targets: {', '.join(self.selected_targets)}")
        print(f"Sending {num_pings} ICMP pings to external targets")
        print("This should trigger Network Reconnaissance detection!")
        print(f"Threshold: 50 ICMP requests in 60 seconds")
        print("=" * 60)
        
        threads = []
        start_time = time.time()
        
        for i in range(num_pings):
            # Rotate through targets
            target_ip = self.selected_targets[i % len(self.selected_targets)]
            
            # Use raw ICMP if possible, otherwise regular ping
            if i % 2 == 0:
                thread = threading.Thread(target=self.send_raw_icmp, args=(target_ip,))
            else:
                thread = threading.Thread(target=self.ping_host, args=(target_ip,))
            
            threads.append(thread)
            thread.start()
            
            # Progress indicator
            if (i + 1) % 10 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"📊 Progress: {i + 1}/{num_pings} pings ({rate:.1f}/sec)")
            
            # Manage thread pool
            if len(threads) >= 8:
                for t in threads[:4]:
                    t.join()
                threads = threads[4:]
            
            time.sleep(0.05)  # Fast pings for detection
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        self.show_ping_results("ICMP Flood", duration)
    
    def ping_sweep_test(self):
        """Simulate network ping sweep across multiple targets"""
        if not self.select_targets():
            return
        
        print("=" * 60)
        print("🌐 NETWORK PING SWEEP TEST")
        print("=" * 60)
        print("Sweeping multiple external targets...")
        print("Simulating network discovery reconnaissance...")
        print("=" * 60)
        
        # Generate more target variations
        sweep_targets = []
        
        # Add variations of selected targets
        for target in self.selected_targets:
            parts = target.split('.')
            base = '.'.join(parts[:3])
            
            # Add nearby IPs
            for i in range(1, 20):
                sweep_targets.append(f"{base}.{i}")
        
        # Limit to reasonable number
        sweep_targets = sweep_targets[:40]
        
        print(f"🎯 Sweeping {len(sweep_targets)} targets...")
        
        threads = []
        start_time = time.time()
        
        for i, target_ip in enumerate(sweep_targets):
            thread = threading.Thread(target=self.ping_host, args=(target_ip,))
            threads.append(thread)
            thread.start()
            
            if (i + 1) % 8 == 0:
                print(f"📊 Sweep progress: {i + 1}/{len(sweep_targets)}")
            
            time.sleep(0.1)  # Sweep delay
        
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        self.show_ping_results("Network Sweep", duration)
    
    def rapid_ping_test(self, duration=30):
        """Send rapid pings for specified duration"""
        if not self.select_targets():
            return
        
        print("=" * 60)
        print("⚡ RAPID PING TEST")
        print("=" * 60)
        print(f"Sending rapid pings to external targets for {duration} seconds")
        print("=" * 60)
        
        start_time = time.time()
        threads = []
        ping_counter = 0
        
        while time.time() - start_time < duration:
            # Rotate through targets
            target_ip = self.selected_targets[ping_counter % len(self.selected_targets)]
            
            thread = threading.Thread(target=self.ping_host, args=(target_ip,))
            threads.append(thread)
            thread.start()
            
            ping_counter += 1
            
            if ping_counter % 15 == 0:
                elapsed = time.time() - start_time
                rate = ping_counter / elapsed
                print(f"⚡ Rapid pings: {ping_counter} sent ({rate:.1f}/sec)")
            
            # Clean up completed threads
            threads = [t for t in threads if t.is_alive()]
            
            time.sleep(0.2)  # Rapid fire pings
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        actual_duration = time.time() - start_time
        print(f"⚡ Rapid ping test completed in {actual_duration:.1f} seconds!")
        self.show_ping_results("Rapid Ping", actual_duration)
    
    def stealth_recon_test(self):
        """Simulate stealthy reconnaissance patterns"""
        if not self.select_targets():
            return
        
        print("=" * 60)
        print("🕵️ STEALTH RECONNAISSANCE TEST")
        print("=" * 60)
        print("Simulating slow, stealthy network reconnaissance...")
        print("=" * 60)
        
        # Mix of different reconnaissance techniques
        for target in self.selected_targets:
            print(f"🎯 Stealthily probing {target}...")
            threads = []
            
            for i in range(15):  # 15 pings per target
                thread = threading.Thread(target=self.ping_host, args=(target,))
                threads.append(thread)
                thread.start()
                time.sleep(1)  # Stealth delay
            
            # Wait for target completion
            for thread in threads:
                thread.join()
        
        self.show_ping_results("Stealth Recon", None)
    
    def advanced_icmp_test(self):
        """Advanced ICMP test with raw sockets"""
        print("=" * 60)
        print("🔧 ADVANCED ICMP TEST")
        print("=" * 60)
        print("Using raw sockets for ICMP (requires admin privileges)")
        print("=" * 60)
        
        try:
            # Test if we can create raw socket
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            test_sock.close()
            print("✅ Raw ICMP socket available!")
            
            # Send raw ICMP to multiple targets
            for target in ["8.8.8.8", "1.1.1.1", "208.67.222.222"]:
                print(f"🎯 Raw ICMP flood to {target}")
                threads = []
                
                for i in range(25):  # 25 raw ICMP per target
                    thread = threading.Thread(target=self.send_raw_icmp, args=(target,))
                    threads.append(thread)
                    thread.start()
                    time.sleep(0.05)
                
                for thread in threads:
                    thread.join()
            
            print("✅ Advanced ICMP test completed")
            
        except PermissionError:
            print("❌ Permission denied - need administrator privileges")
            print("💡 Run as administrator/sudo for raw socket test")
            print("💡 Falling back to regular ping test...")
            self.icmp_flood_test(40)
        except Exception as e:
            print(f"❌ Raw socket test failed: {e}")
            print("💡 Falling back to regular ping test...")
            self.icmp_flood_test(40)
    
    def show_ping_results(self, test_type, duration):
        """Display ping test results"""
        print("=" * 60)
        print(f"📊 {test_type.upper()} RESULTS")
        print("=" * 60)
        print(f"Targets: {', '.join(self.selected_targets)}")
        print(f"Total ICMP packets sent: {self.ping_count}")
        print(f"Successful pings: {self.successful_pings}")
        print(f"Failed pings: {self.failed_pings}")
        if duration:
            print(f"Duration: {duration:.1f} seconds")
            print(f"ICMP rate: {self.ping_count/duration:.1f} packets/second")
        print("=" * 60)
        print("✅ Reconnaissance test completed!")
        print("🛡️ Check your IDS web interface for Network Reconnaissance alerts!")
        print("📈 Look for 'Network Reconnaissance Detected' alerts")
        print("=" * 60)
        
        # Reset counters for next test
        self.ping_count = 0
        self.successful_pings = 0
        self.failed_pings = 0

if __name__ == "__main__":
    print("Network Reconnaissance Detection Test - Working Version")
    print("Targets external IPs to bypass localhost filtering")
    
    tester = ReconnaissanceTest()
    
    print(f"\nDetected OS: {platform.system()}")
    print(f"Ping command: {' '.join(tester.ping_cmd)}")
    print(f"Available targets: {len(tester.target_options)} external IPs")
    
    print("\nChoose reconnaissance test:")
    print("1. ⚡ ICMP Flood (60 rapid pings)")
    print("2. 🌐 Network Ping Sweep (40 targets)")
    print("3. ⚡ Rapid Ping Test (30 seconds)")
    print("4. 🕵️ Stealth Reconnaissance")
    print("5. 🔧 Advanced Raw ICMP Test")
    print("6. 🎯 All Tests")
    print("7. ❌ Cancel")
    
    choice = input("Enter choice (1-7): ").strip()
    
    try:
        if choice == "1":
            tester.icmp_flood_test()
            
        elif choice == "2":
            tester.ping_sweep_test()
            
        elif choice == "3":
            tester.rapid_ping_test()
            
        elif choice == "4":
            tester.stealth_recon_test()
            
        elif choice == "5":
            tester.advanced_icmp_test()
            
        elif choice == "6":
            print("\n⚠️ Running all reconnaissance tests...")
            
            print("\n🚀 Test 1: ICMP Flood")
            tester.icmp_flood_test(50)
            
            print("\n⏳ Waiting 5 seconds...")
            time.sleep(5)
            
            print("\n🚀 Test 2: Rapid Ping Test")
            tester.rapid_ping_test(20)
            
            print("\n⏳ Waiting 5 seconds...")
            time.sleep(5)
            
            print("\n🚀 Test 3: Advanced ICMP")
            tester.advanced_icmp_test()
            
        elif choice == "7":
            print("Test cancelled.")
            sys.exit(0)
            
        else:
            print("Invalid choice. Running ICMP flood test.")
            tester.icmp_flood_test()
            
    except KeyboardInterrupt:
        print("\nReconnaissance test interrupted by user")
        if hasattr(tester, 'ping_count'):
            tester.show_ping_results("Interrupted Test", None)