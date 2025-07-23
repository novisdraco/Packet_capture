#!/usr/bin/env python3
"""
Port Scan Detection Test - Working Version
Targets external IP to bypass localhost exclusion and trigger detection
ONLY USE ON YOUR OWN SYSTEM FOR TESTING
"""

import socket
import threading
import time
import sys

class PortScanTest:
    def __init__(self):
        # Use different target IPs to avoid localhost exclusion
        self.target_options = [
            "192.168.1.1",    # Common router IP
            "8.8.8.8",        # Google DNS (external)
            "1.1.1.1",        # Cloudflare DNS
            "127.0.0.2",      # Localhost variant
            "10.0.0.1"        # Common private network
        ]
        
        self.target_ip = None
        self.open_ports = []
        self.scanned_ports = 0
        
        # Ports that WILL trigger detection (non-legitimate)
        self.suspicious_ports = [
            1234, 1337, 1433, 1521, 1723, 2049, 2121, 2222, 2323, 2525,
            3000, 3001, 3306, 3307, 3389, 4444, 4567, 5001, 5432,
            5555, 5900, 6000, 6001, 6666, 7000, 7001, 7777, 8000, 8001,
            8081, 8888, 9000, 9001, 9999, 10000, 10001, 11111, 12345,
            31337, 54321
        ]
    
    def select_target(self):
        """Select the best target IP for testing"""
        print("🎯 Selecting target IP for port scan test...")
        
        # First, try to find a reachable target
        for ip in self.target_options:
            if self.test_connectivity(ip):
                self.target_ip = ip
                print(f"✅ Selected target: {ip}")
                return True
        
        # If no external IPs work, use localhost variant
        print("⚠️  No external targets reachable, using localhost variant")
        self.target_ip = "127.0.0.2"  # Different from 127.0.0.1
        return True
    
    def test_connectivity(self, ip):
        """Test if target IP is reachable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # Try to connect to a common port
            result = sock.connect_ex((ip, 80))
            sock.close()
            return True  # Even if connection fails, IP is valid for scanning
        except Exception:
            return False
    
    def scan_port(self, port, timeout=0.1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                self.open_ports.append(port)
                print(f"✅ Port {port} is OPEN on {self.target_ip}")
            else:
                print(f"❌ Port {port} is closed on {self.target_ip}")
                
            self.scanned_ports += 1
            
        except Exception as e:
            print(f"⚠️  Port {port}: Error - {e}")
            self.scanned_ports += 1
    
    def run_rapid_fire_scan(self):
        """Rapid fire scan to definitely trigger detection"""
        if not self.select_target():
            print("❌ Could not select target IP")
            return
        
        print("=" * 60)
        print("⚡ RAPID FIRE PORT SCAN")
        print("=" * 60)
        print(f"Target: {self.target_ip}")
        print("Scanning 25 suspicious ports rapidly...")
        print("This will definitely trigger detection!")
        print("=" * 60)
        
        # Select 25 suspicious ports
        import random
        random_ports = random.sample(self.suspicious_ports, 25)
        
        threads = []
        start_time = time.time()
        
        for i, port in enumerate(random_ports):
            thread = threading.Thread(target=self.scan_port, args=(port, 0.05))
            threads.append(thread)
            thread.start()
            
            # Very small delay for rapid scanning
            time.sleep(0.01)
            
            if (i + 1) % 5 == 0:
                print(f"📊 Started {i + 1}/25 scan threads...")
        
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        print(f"📊 Scanned {len(random_ports)} ports in {duration:.2f} seconds")
        print(f"⚡ Scan rate: {len(random_ports)/duration:.1f} ports/second")
        
        self.show_results("Rapid Fire Scan")
    
    def run_external_scan(self):
        """Scan external IP to definitely trigger detection"""
        print("=" * 60)
        print("🌐 EXTERNAL IP PORT SCAN")
        print("=" * 60)
        
        # Force external target
        external_targets = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        
        for target in external_targets:
            try:
                # Quick connectivity test
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.settimeout(2)
                test_sock.connect_ex((target, 53))  # Try DNS port
                test_sock.close()
                
                self.target_ip = target
                print(f"✅ Using external target: {target}")
                break
            except:
                continue
        
        if not self.target_ip:
            print("❌ No external targets available, using fallback")
            self.target_ip = "127.0.0.2"
        
        print(f"Target: {self.target_ip}")
        print("Scanning common service ports on external IP...")
        print("This will trigger detection!")
        print("=" * 60)
        
        # Scan common service ports that are suspicious when scanned externally
        service_ports = [21, 22, 23, 135, 139, 445, 1433, 3389, 5900, 5432, 
                        3306, 1521, 2049, 6000, 8080, 8000, 9000, 10000,
                        1234, 4444, 31337, 12345, 54321]
        
        threads = []
        
        for i, port in enumerate(service_ports):
            thread = threading.Thread(target=self.scan_port, args=(port, 0.1))
            threads.append(thread)
            thread.start()
            time.sleep(0.05)  # Pattern for detection
            
            if (i + 1) % 5 == 0:
                print(f"📊 Scanning progress: {i + 1}/{len(service_ports)}")
        
        for thread in threads:
            thread.join()
        
        self.show_results("External IP Scan")
    
    def run_high_volume_scan(self):
        """High volume scan to guarantee detection"""
        if not self.select_target():
            return
        
        print("=" * 60)
        print("🌊 HIGH VOLUME PORT SCAN")
        print("=" * 60)
        print(f"Target: {self.target_ip}")
        print("Scanning 50 ports to guarantee threshold trigger...")
        print("=" * 60)
        
        # Use more ports to definitely exceed threshold
        ports_to_scan = self.suspicious_ports[:50]  # First 50 suspicious ports
        
        threads = []
        
        for i, port in enumerate(ports_to_scan):
            thread = threading.Thread(target=self.scan_port, args=(port, 0.1))
            threads.append(thread)
            thread.start()
            time.sleep(0.02)  # Small delay for pattern
            
            if (i + 1) % 10 == 0:
                print(f"📊 Progress: {i + 1}/{len(ports_to_scan)} ports started")
        
        for thread in threads:
            thread.join()
        
        self.show_results("High Volume Scan")
    
    def show_results(self, scan_type):
        """Show scan results"""
        print("=" * 60)
        print(f"📊 {scan_type.upper()} RESULTS:")
        print(f"Target IP: {self.target_ip}")
        print(f"Total ports scanned: {self.scanned_ports}")
        print(f"Open ports found: {len(self.open_ports)}")
        if self.open_ports:
            print(f"Open ports: {', '.join(map(str, self.open_ports))}")
        print("=" * 60)
        print("✅ Port scan test completed!")
        print("🛡️ Check your IDS web interface for Port Scan alerts!")
        print("📈 Look for 'Potential Port Scan Detected' alerts")
        print("=" * 60)
        
        # Reset counters
        self.scanned_ports = 0
        self.open_ports = []

class LocalhostBypassTest:
    """Special test to bypass localhost filtering"""
    
    def __init__(self):
        self.target_ip = "127.0.0.2"  # Different localhost address
        self.scanned_ports = 0
    
    def scan_port_bypass(self, port):
        """Scan port with bypass technique"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            self.scanned_ports += 1
            print(f"🔍 Scanned port {port} on {self.target_ip}")
            
        except Exception as e:
            self.scanned_ports += 1
    
    def run_bypass_test(self):
        """Run localhost bypass test"""
        print("=" * 60)
        print("🕳️  LOCALHOST BYPASS TEST")
        print("=" * 60)
        print("Using 127.0.0.2 instead of 127.0.0.1 to bypass filtering...")
        print("Scanning 30 ports rapidly...")
        print("=" * 60)
        
        # Scan 30 different ports rapidly
        ports = list(range(8000, 8030))
        threads = []
        
        for port in ports:
            thread = threading.Thread(target=self.scan_port_bypass, args=(port,))
            threads.append(thread)
            thread.start()
            time.sleep(0.01)
        
        for thread in threads:
            thread.join()
        
        print("=" * 60)
        print(f"✅ Bypass test completed!")
        print(f"📊 Scanned {self.scanned_ports} ports on {self.target_ip}")
        print("🛡️ Check IDS for Port Scan alerts!")
        print("=" * 60)

if __name__ == "__main__":
    print("Port Scan Detection Test - Working Version")
    print("Designed to bypass localhost filtering and trigger detection")
    
    print("\nChoose test type:")
    print("1. ⚡ Rapid Fire Scan (25 ports)")
    print("2. 🌐 External IP Scan (public DNS servers)")
    print("3. 🌊 High Volume Scan (50 ports)")
    print("4. 🕳️  Localhost Bypass Test (127.0.0.2)")
    print("5. 🎯 All Tests")
    print("6. ❌ Cancel")
    
    choice = input("Enter choice (1-6): ").strip()
    
    try:
        if choice == "1":
            scanner = PortScanTest()
            scanner.run_rapid_fire_scan()
        elif choice == "2":
            scanner = PortScanTest()
            scanner.run_external_scan()
        elif choice == "3":
            scanner = PortScanTest()
            scanner.run_high_volume_scan()
        elif choice == "4":
            bypass_test = LocalhostBypassTest()
            bypass_test.run_bypass_test()
        elif choice == "5":
            print("\n⚠️ Running all tests...")
            scanner = PortScanTest()
            
            print("\n🚀 Test 1: Rapid Fire")
            scanner.run_rapid_fire_scan()
            
            print("\n⏳ Waiting 3 seconds...")
            time.sleep(3)
            
            print("\n🚀 Test 2: External IP")
            scanner.run_external_scan()
            
            print("\n⏳ Waiting 3 seconds...")
            time.sleep(3)
            
            print("\n🚀 Test 3: Localhost Bypass")
            bypass_test = LocalhostBypassTest()
            bypass_test.run_bypass_test()
            
        elif choice == "6":
            print("Test cancelled.")
            sys.exit(0)
        else:
            print("Invalid choice. Running rapid fire scan.")
            scanner = PortScanTest()
            scanner.run_rapid_fire_scan()
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")