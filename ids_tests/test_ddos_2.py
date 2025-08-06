#!/usr/bin/env python3
"""
DDoS Detection Validation Test
Tests the enhanced DDoS detection system to verify false positive fixes
"""

import socket
import threading
import time
import sys

class DDoSValidationTest:
    def __init__(self):
        self.results = {
            'legitimate_traffic_alerts': 0,
            'attack_traffic_alerts': 0,
            'total_legitimate_packets': 0,
            'total_attack_packets': 0
        }
    
    def test_legitimate_web_browsing(self, duration=60):
        """Simulate legitimate web browsing traffic"""
        print("\n🌐 Testing Legitimate Web Browsing Traffic")
        print(f"Duration: {duration} seconds")
        print("Expected: NO DDoS alerts should be generated")
        print("-" * 50)
        
        # Common web destinations
        web_destinations = [
            ("8.8.8.8", 443),      # Google DNS HTTPS
            ("1.1.1.1", 443),      # Cloudflare HTTPS
            ("208.67.222.222", 80), # OpenDNS HTTP
        ]
        
        start_time = time.time()
        packets_sent = 0
        
        while time.time() - start_time < duration:
            for dst_ip, dst_port in web_destinations:
                try:
                    # Simulate normal web requests
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    
                    # Normal web request pattern
                    sock.connect_ex((dst_ip, dst_port))
                    
                    # Send HTTP-like request
                    if dst_port == 80:
                        sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    else:
                        sock.send(b"ClientHello SSL/TLS")
                    
                    sock.close()
                    packets_sent += 1
                    
                    if packets_sent % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = packets_sent / elapsed
                        print(f"📊 Legitimate traffic: {packets_sent} packets ({rate:.1f} pps)")
                    
                    # Normal browsing delays (0.5-2 seconds between requests)
                    time.sleep(0.5 + (time.time() % 1.5))
                    
                except Exception:
                    packets_sent += 1
        
        self.results['total_legitimate_packets'] = packets_sent
        print(f"✅ Legitimate traffic test completed: {packets_sent} packets sent")
        print("🔍 Check IDS - Should show NO DDoS alerts for this traffic")
    
    def test_teams_conference_traffic(self, duration=45):
        """Simulate MS Teams/video conference traffic"""
        print("\n📹 Testing Video Conference Traffic (MS Teams)")
        print(f"Duration: {duration} seconds")
        print("Expected: NO DDoS alerts (should be filtered)")
        print("-" * 50)
        
        # Teams-like traffic patterns
        teams_endpoints = [
            ("20.190.128.0", 443),   # Microsoft Teams servers
            ("52.112.0.0", 3478),    # STUN/TURN servers
            ("13.107.42.14", 443),   # Teams media
        ]
        
        start_time = time.time()
        packets_sent = 0
        
        def send_teams_traffic(endpoint):
            nonlocal packets_sent
            dst_ip, dst_port = endpoint
            
            while time.time() - start_time < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.2)
                    sock.connect_ex((dst_ip, dst_port))
                    
                    # Teams-like data
                    sock.send(b"teams.microsoft.com media stream")
                    sock.close()
                    packets_sent += 1
                    
                    # Conference traffic pattern (higher rate but not attack)
                    time.sleep(0.05)  # 20 pps per endpoint
                    
                except Exception:
                    packets_sent += 1
        
        # Start multiple threads to simulate conference traffic
        threads = []
        for endpoint in teams_endpoints:
            thread = threading.Thread(target=send_teams_traffic, args=(endpoint,))
            threads.append(thread)
            thread.start()
        
        # Monitor progress
        while any(t.is_alive() for t in threads):
            time.sleep(5)
            elapsed = time.time() - start_time
            rate = packets_sent / elapsed if elapsed > 0 else 0
            print(f"📹 Conference traffic: {packets_sent} packets ({rate:.1f} pps)")
        
        for thread in threads:
            thread.join()
        
        print(f"✅ Conference traffic test completed: {packets_sent} packets sent")
        print("🔍 Should be filtered by smart filtering - NO DDoS alerts expected")
    
    def test_real_ddos_attack(self, target_ip="8.8.8.8", target_port=53, duration=30):
        """Test actual DDoS attack pattern - should trigger alerts"""
        print(f"\n🚨 Testing REAL DDoS Attack Pattern")
        print(f"Target: {target_ip}:{target_port}")
        print(f"Duration: {duration} seconds")
        print("Expected: DDoS alerts SHOULD be generated")
        print("-" * 50)
        
        packets_sent = 0
        start_time = time.time()
        
        def attack_thread():
            nonlocal packets_sent
            thread_start = time.time()
            
            while time.time() - thread_start < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.1)
                    
                    # DDoS-style rapid packets
                    attack_data = b"ATTACK_PACKET_" + str(packets_sent).encode()
                    sock.sendto(attack_data, (target_ip, target_port))
                    sock.close()
                    
                    packets_sent += 1
                    
                    # Very rapid rate (attack pattern)
                    time.sleep(0.005)  # 200 pps - should trigger detection
                    
                except Exception:
                    packets_sent += 1
        
        # Launch multiple attack threads (DDoS characteristic)
        print("🚀 Launching coordinated attack threads...")
        attack_threads = []
        for i in range(5):  # 5 attack threads
            thread = threading.Thread(target=attack_thread)
            attack_threads.append(thread)
            thread.start()
        
        # Monitor attack progress
        while any(t.is_alive() for t in attack_threads):
            time.sleep(3)
            elapsed = time.time() - start_time
            rate = packets_sent / elapsed if elapsed > 0 else 0
            print(f"⚡ Attack traffic: {packets_sent} packets ({rate:.1f} pps)")
        
        for thread in attack_threads:
            thread.join()
        
        self.results['total_attack_packets'] = packets_sent
        print(f"💥 DDoS attack test completed: {packets_sent} packets sent")
        print("🚨 This SHOULD trigger DDoS detection alerts!")
    
    def test_gradual_ramp_up(self, target_ip="1.1.1.1", duration=60):
        """Test gradual traffic increase (should NOT trigger initially)"""
        print(f"\n📈 Testing Gradual Traffic Ramp-Up")
        print(f"Target: {target_ip}:80")
        print(f"Duration: {duration} seconds")
        print("Expected: Should adapt to increasing legitimate traffic")
        print("-" * 50)
        
        packets_sent = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            progress = elapsed / duration
            
            # Gradually increase rate from 5 pps to 50 pps
            target_rate = 5 + (45 * progress)
            delay = 1.0 / target_rate
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                sock.connect_ex((target_ip, 80))
                sock.send(b"GET /api/data HTTP/1.1\r\nHost: service.com\r\n\r\n")
                sock.close()
                
                packets_sent += 1
                
                if packets_sent % 20 == 0:
                    print(f"📈 Gradual ramp: {packets_sent} packets, rate: {target_rate:.1f} pps")
                
                time.sleep(delay)
                
            except Exception:
                packets_sent += 1
        
        print(f"✅ Gradual ramp test completed: {packets_sent} packets")
        print("🔍 Should show learning/adaptation - minimal false positives")
    
    def run_comprehensive_validation(self):
        """Run all validation tests"""
        print("=" * 70)
        print("🧪 DDoS DETECTION VALIDATION TEST SUITE")
        print("=" * 70)
        print("This test validates the enhanced DDoS detection system")
        print("and verifies that false positives have been eliminated.")
        print("=" * 70)
        
        print("\n⚠️  IMPORTANT:")
        print("• Monitor your IDS dashboard during these tests")
        print("• Only the 'Real DDoS Attack' test should generate alerts")
        print("• All other traffic should be classified as legitimate")
        print("=" * 70)
        
        # Test 1: Legitimate web browsing
        print("\n🔄 Starting Test 1 of 4...")
        self.test_legitimate_web_browsing(duration=45)
        
        print("\n⏳ Waiting 10 seconds before next test...")
        time.sleep(10)
        
        # Test 2: Video conference traffic
        print("\n🔄 Starting Test 2 of 4...")
        self.test_teams_conference_traffic(duration=30)
        
        print("\n⏳ Waiting 10 seconds before next test...")
        time.sleep(10)
        
        # Test 3: Gradual ramp-up
        print("\n🔄 Starting Test 3 of 4...")
        self.test_gradual_ramp_up(duration=40)
        
        print("\n⏳ Waiting 15 seconds before final test...")
        time.sleep(15)
        
        # Test 4: Real DDoS attack (should trigger)
        print("\n🔄 Starting Test 4 of 4 (SHOULD TRIGGER ALERTS)...")
        self.test_real_ddos_attack(duration=20)
        
        # Display final results
        self.display_results()
    
    def display_results(self):
        """Display comprehensive test results"""
        print("\n" + "=" * 70)
        print("📊 DDoS VALIDATION TEST RESULTS")
        print("=" * 70)
        
        print(f"📤 Total Legitimate Packets: {self.results['total_legitimate_packets']}")
        print(f"💥 Total Attack Packets: {self.results['total_attack_packets']}")
        
        print("\n🎯 Expected Results:")
        print("✅ Legitimate web traffic: NO DDoS alerts")
        print("✅ Video conference traffic: NO DDoS alerts (filtered)")
        print("✅ Gradual ramp-up: NO or minimal DDoS alerts")
        print("🚨 Real DDoS attack: SHOULD generate DDoS alerts")
        
        print("\n🔍 Validation Checklist:")
        print("[ ] Check IDS dashboard for alerts during each test")
        print("[ ] Verify only Test 4 (Real DDoS) generated alerts")
        print("[ ] Confirm smart filtering worked for Tests 1-3")
        print("[ ] Review alert details for accuracy")
        
        print("\n📈 Performance Notes:")
        print("• Enhanced DDoS detection uses multiple validation layers")
        print("• Smart filtering learns normal traffic patterns")
        print("• False positive rate should be significantly reduced")
        
        print("\n✅ DDoS validation testing completed!")
        print("=" * 70)

class QuickValidationTest:
    """Quick test to verify DDoS detection is working"""
    
    def quick_false_positive_check(self):
        """Quick test for false positives"""
        print("⚡ QUICK FALSE POSITIVE CHECK")
        print("-" * 40)
        
        # Send normal web traffic that previously triggered false positives
        target_ip = "8.8.8.8"
        packets_sent = 0
        
        print(f"📡 Sending 100 normal DNS queries to {target_ip}...")
        
        for i in range(100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.2)
                
                # Normal DNS query pattern
                query_data = f"DNS_QUERY_{i:03d}_google.com".encode()
                sock.sendto(query_data, (target_ip, 53))
                sock.close()
                
                packets_sent += 1
                
                if (i + 1) % 25 == 0:
                    print(f"📊 Progress: {i + 1}/100 DNS queries sent")
                
                # Normal query timing (not attack-like)
                time.sleep(0.2)  # 5 pps - normal rate
                
            except Exception:
                packets_sent += 1
        
        print(f"✅ Quick test completed: {packets_sent} DNS queries sent")
        print("🔍 Result: Should show NO DDoS alerts in IDS dashboard")
        print("💡 If DDoS alerts appear, false positive issue persists")

if __name__ == "__main__":
    print("🛡️ DDoS Detection Validation Test Suite")
    print("Verifies enhanced DDoS detection and false positive fixes")
    
    print("\n📋 Available Tests:")
    print("1. ⚡ Quick False Positive Check (2 minutes)")
    print("2. 🌐 Legitimate Web Traffic Test (3 minutes)")
    print("3. 📹 Video Conference Traffic Test (3 minutes)")
    print("4. 🚨 Real DDoS Attack Test (2 minutes)")
    print("5. 📈 Gradual Traffic Ramp Test (4 minutes)")
    print("6. 🧪 Comprehensive Validation Suite (12 minutes)")
    print("7. ❌ Exit")
    
    print("\n⚠️ Prerequisites:")
    print("• Enhanced IDS must be running with new DDoS detection")
    print("• Monitor http://localhost:5000 during tests")
    print("• Packet capture should be active")
    
    choice = input("\nSelect test (1-7): ").strip()
    
    validator = DDoSValidationTest()
    quick_test = QuickValidationTest()
    
    try:
        if choice == "1":
            quick_test.quick_false_positive_check()
            
        elif choice == "2":
            validator.test_legitimate_web_browsing()
            
        elif choice == "3":
            validator.test_teams_conference_traffic()
            
        elif choice == "4":
            print("\n⚠️ This will generate a real DDoS attack pattern!")
            confirm = input("Continue? (y/N): ").strip().lower()
            if confirm == 'y':
                validator.test_real_ddos_attack()
            else:
                print("Test cancelled.")
                
        elif choice == "5":
            validator.test_gradual_ramp_up()
            
        elif choice == "6":
            print("\n🚀 Starting comprehensive validation...")
            print("This will take approximately 12 minutes.")
            confirm = input("Continue? (y/N): ").strip().lower()
            if confirm == 'y':
                validator.run_comprehensive_validation()
            else:
                print("Test cancelled.")
                
        elif choice == "7":
            print("👋 Exiting...")
            sys.exit(0)
            
        else:
            print("Invalid choice. Running quick test...")
            quick_test.quick_false_positive_check()
            
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
        print("Check IDS dashboard for any alerts generated during partial test")
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        print("Ensure your enhanced IDS is running and accessible")