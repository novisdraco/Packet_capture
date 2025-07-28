#!/usr/bin/env python3
"""
Simple IDS Validation Test
Tests each attack type individually to verify false positive fixes
Save this as: test_validation.py
"""

import socket
import time
import sys
import subprocess
import threading

class SimpleValidationTest:
    def __init__(self):
        self.target_ip = "8.8.8.8"  # External IP to avoid localhost filtering
        
    def test_brute_force_only(self):
        """Test brute force detection - should NOT trigger DDoS"""
        print("\n" + "="*50)
        print("🔑 TESTING: Brute Force Detection")
        print("="*50)
        print(f"Making 55 SSH attempts to {self.target_ip}:22")
        print("Expected: ONLY 'Brute Force Attack Detected'")
        print("Should NOT trigger: DDoS alerts")
        print("-"*50)
        
        for i in range(55):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                sock.connect_ex((self.target_ip, 22))  # SSH port
                sock.close()
                
                if (i + 1) % 10 == 0:
                    print(f"🔐 SSH attempts: {i + 1}/55")
                
                # Slower pace to avoid DDoS detection
                time.sleep(3.0)  # 3 seconds between attempts
                
            except Exception:
                pass
        
        print("✅ Brute force test completed!")
        print("📊 Check IDS: Should show 'Brute Force Attack Detected' ONLY")
        input("Press Enter to continue...")
    
    def test_port_scan_only(self):
        """Test port scan detection - should NOT trigger DDoS"""
        print("\n" + "="*50)
        print("🔍 TESTING: Port Scan Detection")
        print("="*50)
        print(f"Scanning 30 ports on {self.target_ip}")
        print("Expected: ONLY 'Port Scan Detected'")
        print("Should NOT trigger: DDoS alerts")
        print("-"*50)
        
        # Suspicious ports for scanning
        ports = [1234, 1337, 1433, 1521, 2049, 2121, 2222, 3000, 3001, 3306,
                 4444, 4567, 5001, 5432, 5555, 6000, 6001, 7000, 7001, 7777,
                 8001, 8888, 9000, 9001, 9999, 10000, 10001, 31337, 12345, 54321]
        
        for i, port in enumerate(ports[:30]):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                sock.connect_ex((self.target_ip, port))
                sock.close()
                
                if (i + 1) % 5 == 0:
                    print(f"🔍 Ports scanned: {i + 1}/30")
                
                # Sequential scanning pattern
                time.sleep(1.0)  # 1 second between ports
                
            except Exception:
                pass
        
        print("✅ Port scan test completed!")
        print("📊 Check IDS: Should show 'Port Scan Detected' ONLY")
        input("Press Enter to continue...")
    
    def test_dns_tunneling_only(self):
        """Test DNS tunneling detection - should NOT trigger DDoS"""
        print("\n" + "="*50)
        print("🌐 TESTING: DNS Tunneling Detection")
        print("="*50)
        print(f"Sending 130 DNS queries to {self.target_ip}:53")
        print("Expected: ONLY 'DNS Tunneling Detected'")
        print("Should NOT trigger: DDoS alerts")
        print("-"*50)
        
        for i in range(130):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.1)
                
                # DNS query pattern
                query = f"tunnel{i:03d}.malicious.com"
                dns_packet = f"DNS_QUERY_{query}".encode()
                sock.sendto(dns_packet, (self.target_ip, 53))
                sock.close()
                
                if (i + 1) % 20 == 0:
                    print(f"🌐 DNS queries: {i + 1}/130")
                
                # Consistent rate typical of tunneling
                time.sleep(0.4)  # 0.4s intervals (consistent tunneling pattern)
                
            except Exception:
                pass
        
        print("✅ DNS tunneling test completed!")
        print("📊 Check IDS: Should show 'DNS Tunneling Detected' ONLY")
        input("Press Enter to continue...")
    
    def test_icmp_recon_only(self):
        """Test ICMP reconnaissance - should NOT trigger DDoS"""
        print("\n" + "="*50)
        print("📡 TESTING: Network Reconnaissance Detection")
        print("="*50)
        print("Sending ICMP pings for reconnaissance pattern")
        print("Expected: ONLY 'Network Reconnaissance Detected'")
        print("Should NOT trigger: DDoS alerts")
        print("-"*50)
        
        targets = [self.target_ip, "1.1.1.1", "208.67.222.222"]
        
        # Systematic reconnaissance pattern
        for round_num in range(25):  # 25 rounds = 75 total pings
            for target in targets:
                try:
                    if sys.platform == "win32":
                        cmd = ["ping", "-n", "1", "-w", "500", target]
                    else:
                        cmd = ["ping", "-c", "1", "-W", "1", target]
                    
                    subprocess.run(cmd, capture_output=True, timeout=2)
                    
                    if (round_num * len(targets)) % 15 == 0:
                        total = (round_num + 1) * len(targets)
                        print(f"📡 ICMP pings sent: {total}")
                    
                    # Reconnaissance timing
                    time.sleep(0.3)
                    
                except Exception:
                    pass
        
        print("✅ ICMP reconnaissance test completed!")
        print("📊 Check IDS: Should show 'Network Reconnaissance Detected' ONLY")
        input("Press Enter to continue...")
    
    def test_ddos_attack(self):
        """Test DDoS detection (control test)"""
        print("\n" + "="*50)
        print("🌊 TESTING: DDoS Attack Detection (Control Test)")
        print("="*50)
        print(f"Generating high volume traffic to {self.target_ip}:53")
        print("Expected: 'DDoS Attack Detected'")
        print("This should trigger DDoS detection")
        print("-"*50)
        
        # High volume, fast rate
        def send_packet():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.1)
                sock.sendto(b"DDOS_TEST_PACKET", (self.target_ip, 53))
                sock.close()
            except Exception:
                pass
        
        threads = []
        for i in range(600):  # High volume
            thread = threading.Thread(target=send_packet)
            threads.append(thread)
            thread.start()
            
            if (i + 1) % 50 == 0:
                print(f"🌊 Packets sent: {i + 1}/600")
            
            time.sleep(0.01)  # Very fast rate
        
        # Wait for threads
        for thread in threads:
            thread.join()
        
        print("✅ DDoS test completed!")
        print("📊 Check IDS: Should show 'DDoS Attack Detected'")
        input("Press Enter to continue...")
    
    def run_all_tests(self):
        """Run all validation tests"""
        print("🧪 IDS FALSE POSITIVE VALIDATION SUITE")
        print("="*60)
        print("This will test each attack type individually")
        print("⚠️  Monitor your IDS web interface during each test")
        print("✅ Each test should trigger ONLY its specific alert type")
        print("="*60)
        
        tests = [
            ("Brute Force", self.test_brute_force_only),
            ("Port Scan", self.test_port_scan_only), 
            ("DNS Tunneling", self.test_dns_tunneling_only),
            ("ICMP Reconnaissance", self.test_icmp_recon_only),
            ("DDoS (Control)", self.test_ddos_attack)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🚀 Ready to run {test_name} test...")
            ready = input("Press Enter to start (or 'q' to quit): ")
            if ready.lower() == 'q':
                break
                
            try:
                test_func()
            except KeyboardInterrupt:
                print(f"\n⚠️ {test_name} test interrupted")
                break
            except Exception as e:
                print(f"\n❌ {test_name} test failed: {e}")
        
        print("\n🏁 Validation complete!")
        print("📊 SUMMARY:")
        print("   • Each test should trigger only its specific alert")
        print("   • No cross-contamination between alert types")
        print("   • DDoS should only trigger on high-volume test")

if __name__ == "__main__":
    print("IDS False Positive Validation Test")
    print("Verifies that each attack triggers only its specific alert")
    
    tester = SimpleValidationTest()
    
    print(f"\n🎯 Target IP: {tester.target_ip}")
    print("Choose test:")
    print("1. 🔑 Brute Force Test")
    print("2. 🔍 Port Scan Test")
    print("3. 🌐 DNS Tunneling Test")
    print("4. 📡 ICMP Reconnaissance Test")
    print("5. 🌊 DDoS Test (Control)")
    print("6. 🧪 Run All Tests")
    print("7. ❌ Exit")
    
    choice = input("\nEnter choice (1-7): ").strip()
    
    try:
        if choice == "1":
            tester.test_brute_force_only()
        elif choice == "2":
            tester.test_port_scan_only()
        elif choice == "3":
            tester.test_dns_tunneling_only()
        elif choice == "4":
            tester.test_icmp_recon_only()
        elif choice == "5":
            tester.test_ddos_attack()
        elif choice == "6":
            tester.run_all_tests()
        elif choice == "7":
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Running brute force test.")
            tester.test_brute_force_only()
            
    except KeyboardInterrupt:
        print("\nValidation test interrupted by user")
    
    print("\n✅ Test completed! Check your IDS dashboard for results.")