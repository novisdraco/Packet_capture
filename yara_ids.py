#!/usr/bin/env python3
"""
YARA-based IDS Integration Module
Adds YARA rule matching capabilities to the existing packet capture IDS
"""

import yara
import os
import hashlib
import binascii
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
import threading
import time

class YARARule:
    """Individual YARA rule wrapper"""
    def __init__(self, name: str, rule_content: str, enabled: bool = True):
        self.name = name
        self.rule_content = rule_content
        self.enabled = enabled
        self.compiled_rule = None
        self.match_count = 0
        self.last_match = None
        self.compile_rule()
    
    def compile_rule(self):
        """Compile the YARA rule"""
        try:
            self.compiled_rule = yara.compile(source=self.rule_content)
            return True
        except yara.SyntaxError as e:
            print(f"❌ YARA syntax error in rule '{self.name}': {e}")
            return False
        except Exception as e:
            print(f"❌ Error compiling YARA rule '{self.name}': {e}")
            return False
    
    def match(self, data: bytes) -> List[yara.Match]:
        """Match data against this YARA rule"""
        if not self.enabled or not self.compiled_rule:
            return []
        
        try:
            matches = self.compiled_rule.match(data=data)
            if matches:
                self.match_count += len(matches)
                self.last_match = datetime.now()
            return matches
        except Exception as e:
            print(f"❌ Error matching YARA rule '{self.name}': {e}")
            return []

class YARAEngine:
    """YARA detection engine for the IDS"""
    
    def __init__(self):
        self.rules: Dict[str, YARARule] = {}
        self.total_matches = 0
        self.compiled_rules = None
        self.rules_dir = "yara_rules"
        self.initialize_default_rules()
        self.load_external_rules()
    
    def initialize_default_rules(self):
        """Initialize built-in YARA rules for network security"""
        
        # Malware signatures
        malware_rule = """
rule Malware_Signatures {
    meta:
        description = "Detects common malware patterns in network traffic"
        author = "IDS System"
        severity = "High"
        
    strings:
        $mz = { 4D 5A }                    // MZ header
        $pe = "PE"                         // PE signature
        $metasploit = "metasploit"
        $meterpreter = "meterpreter"
        $payload = "payload"
        $exploit = "exploit"
        $shellcode = { 90 90 90 90 }       // NOP sled
        $reverse_shell = "reverse_shell"
        $backdoor = "backdoor"
        $trojan = "trojan"
        
    condition:
        ($mz at 0 and $pe) or
        any of ($metasploit, $meterpreter, $payload, $exploit, $reverse_shell, $backdoor, $trojan) or
        #shellcode > 10
}
"""
        
        # SQL injection patterns
        sqli_rule = """
rule SQL_Injection_Patterns {
    meta:
        description = "Detects SQL injection attempts in network traffic"
        author = "IDS System"
        severity = "High"
        
    strings:
        $sqli1 = "' OR '1'='1"
        $sqli2 = "' OR 1=1"
        $sqli3 = "UNION SELECT"
        $sqli4 = "'; DROP TABLE"
        $sqli5 = "'; INSERT INTO"
        $sqli6 = "'; DELETE FROM"
        $sqli7 = "' UNION ALL SELECT"
        $sqli8 = /SELECT.*FROM.*WHERE.*=/
        $sqli9 = "admin'--"
        $sqli10 = "1' AND '1'='1"
        
    condition:
        any of them
}
"""
        
        # XSS patterns
        xss_rule = """
rule XSS_Attack_Patterns {
    meta:
        description = "Detects Cross-Site Scripting (XSS) attempts"
        author = "IDS System"
        severity = "Medium"
        
    strings:
        $xss1 = "<script>"
        $xss2 = "javascript:"
        $xss3 = "alert("
        $xss4 = "document.cookie"
        $xss5 = "eval("
        $xss6 = "<iframe"
        $xss7 = "onload="
        $xss8 = "onerror="
        $xss9 = "onmouseover="
        $xss10 = /<script[^>]*>.*<\/script>/
        
    condition:
        any of them
}
"""
        
        # Command injection
        cmd_injection_rule = """
rule Command_Injection_Patterns {
    meta:
        description = "Detects command injection attempts"
        author = "IDS System"
        severity = "High"
        
    strings:
        $cmd1 = "cmd.exe"
        $cmd2 = "/bin/sh"
        $cmd3 = "/bin/bash"
        $cmd4 = "powershell"
        $cmd5 = "system("
        $cmd6 = "exec("
        $cmd7 = "shell_exec("
        $cmd8 = "passthru("
        $cmd9 = "`" // backtick
        $cmd10 = "; cat /etc/passwd"
        $cmd11 = "&& net user"
        $cmd12 = "|| whoami"
        
    condition:
        any of them
}
"""
        
        # Network reconnaissance
        recon_rule = """
rule Network_Reconnaissance {
    meta:
        description = "Detects network reconnaissance tools and patterns"
        author = "IDS System"
        severity = "Medium"
        
    strings:
        $nmap1 = "nmap"
        $nmap2 = "Nmap"
        $nessus = "Nessus"
        $nikto = "Nikto"
        $dirb = "dirb"
        $gobuster = "gobuster"
        $sqlmap = "sqlmap"
        $burp = "Burp Suite"
        $metasploit = "Metasploit"
        $recon1 = "reconnaissance"
        $recon2 = "port scan"
        $recon3 = "vulnerability scan"
        
    condition:
        any of them
}
"""
        
        # Suspicious file transfers
        file_transfer_rule = """
rule Suspicious_File_Transfer {
    meta:
        description = "Detects suspicious file transfer patterns"
        author = "IDS System"
        severity = "Medium"
        
    strings:
        $ftp1 = "STOR"
        $ftp2 = "RETR"
        $http1 = "Content-Disposition: attachment"
        $http2 = "application/octet-stream"
        $base64 = /[A-Za-z0-9+\/]{50,}={0,2}/
        $exe = { 4D 5A 90 00 }  // MZ executable header
        $zip = { 50 4B 03 04 }  // ZIP file header
        $rar = { 52 61 72 21 }  // RAR file header
        
    condition:
        any of ($ftp1, $ftp2, $http1, $http2) or
        ($base64 and ($exe or $zip or $rar))
}
"""
        
        # Crypto mining indicators
        crypto_rule = """
rule Cryptocurrency_Mining {
    meta:
        description = "Detects cryptocurrency mining activity"
        author = "IDS System"
        severity = "Medium"
        
    strings:
        $pool1 = "stratum+tcp"
        $pool2 = "pool.supportxmr.com"
        $pool3 = "xmr-usa-east1.nanopool.org"
        $pool4 = "monerohash.com"
        $miner1 = "xmrig"
        $miner2 = "cgminer"
        $miner3 = "bfgminer"
        $crypto1 = "monero"
        $crypto2 = "bitcoin"
        $crypto3 = "ethereum"
        $crypto4 = "mining"
        
    condition:
        any of them
}
"""

        # C2 communication patterns
        c2_rule = """
rule C2_Communication {
    meta:
        description = "Detects command and control communication patterns"
        author = "IDS System"
        severity = "High"
        
    strings:
        $c2_1 = "cmd:"
        $c2_2 = "download:"
        $c2_3 = "upload:"
        $c2_4 = "execute:"
        $c2_5 = "kill:"
        $c2_6 = "screenshot"
        $c2_7 = "keylog"
        $c2_8 = "persistence"
        $base64_cmd = /Y21kOg==/  // base64 "cmd:"
        $encrypted = /[A-F0-9]{32,}/
        
    condition:
        any of ($c2_1, $c2_2, $c2_3, $c2_4, $c2_5, $c2_6, $c2_7, $c2_8, $base64_cmd) or
        (#encrypted > 3)
}
"""
        
        # Add all default rules
        self.add_rule("malware_signatures", malware_rule)
        self.add_rule("sql_injection", sqli_rule)
        self.add_rule("xss_attacks", xss_rule)
        self.add_rule("command_injection", cmd_injection_rule)
        self.add_rule("network_recon", recon_rule)
        self.add_rule("file_transfer", file_transfer_rule)
        self.add_rule("crypto_mining", crypto_rule)
        self.add_rule("c2_communication", c2_rule)
        
        print(f"✅ Initialized {len(self.rules)} default YARA rules")
    
    def load_external_rules(self):
        """Load YARA rules from external files"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            print(f"📁 Created YARA rules directory: {self.rules_dir}")
            self.create_sample_rule_files()
            return
        
        rule_files = [f for f in os.listdir(self.rules_dir) if f.endswith('.yar') or f.endswith('.yara')]
        
        for rule_file in rule_files:
            try:
                file_path = os.path.join(self.rules_dir, rule_file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    rule_content = f.read()
                
                rule_name = os.path.splitext(rule_file)[0]
                self.add_rule(rule_name, rule_content)
                print(f"📜 Loaded external YARA rule: {rule_file}")
                
            except Exception as e:
                print(f"❌ Error loading YARA rule file {rule_file}: {e}")
        
        print(f"✅ Total YARA rules loaded: {len(self.rules)}")
    
    def create_sample_rule_files(self):
        """Create sample YARA rule files for demonstration"""
        
        # Advanced malware detection rule
        advanced_malware = """
rule Advanced_Malware_Detection {
    meta:
        description = "Advanced malware detection patterns"
        author = "Security Team"
        date = "2024-01-01"
        severity = "Critical"
        
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"
        $api3 = "WriteProcessMemory"
        $api4 = "SetWindowsHookEx"
        $api5 = "GetProcAddress"
        
        $packer1 = "UPX"
        $packer2 = "ASPack"
        $packer3 = "PESpin"
        
        $crypto1 = { 6A 40 68 00 30 00 00 }  // VirtualAlloc pattern
        $crypto2 = { 55 8B EC 83 EC ?? 56 57 }  // Function prologue
        
    condition:
        (3 of ($api*)) or
        any of ($packer*) or
        any of ($crypto*)
}
"""
        
        # Web shell detection
        webshell_rule = """
rule Web_Shell_Detection {
    meta:
        description = "Detects web shell patterns in HTTP traffic"
        author = "Security Team"
        severity = "High"
        
    strings:
        $php1 = "<?php eval("
        $php2 = "<?php system("
        $php3 = "<?php exec("
        $php4 = "<?php shell_exec("
        $php5 = "<?php passthru("
        
        $asp1 = "<%eval request"
        $asp2 = "<%execute request"
        
        $jsp1 = "<%Runtime.getRuntime().exec("
        $jsp2 = "<%Process p = Runtime"
        
        $generic1 = "webshell"
        $generic2 = "backdoor"
        $generic3 = "c99shell"
        $generic4 = "r57shell"
        
    condition:
        any of them
}
"""
        
        # Save sample rules
        samples = [
            ("advanced_malware.yara", advanced_malware),
            ("webshell_detection.yara", webshell_rule)
        ]
        
        for filename, content in samples:
            file_path = os.path.join(self.rules_dir, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"📝 Created sample rule file: {filename}")
    
    def add_rule(self, name: str, rule_content: str, enabled: bool = True):
        """Add a new YARA rule to the engine"""
        rule = YARARule(name, rule_content, enabled)
        if rule.compiled_rule:
            self.rules[name] = rule
            return True
        return False
    
    def remove_rule(self, name: str):
        """Remove a YARA rule from the engine"""
        if name in self.rules:
            del self.rules[name]
            return True
        return False
    
    def enable_rule(self, name: str):
        """Enable a YARA rule"""
        if name in self.rules:
            self.rules[name].enabled = True
            return True
        return False
    
    def disable_rule(self, name: str):
        """Disable a YARA rule"""
        if name in self.rules:
            self.rules[name].enabled = False
            return True
        return False
    
    def scan_data(self, data: bytes, source_info: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Scan data against all enabled YARA rules - FIXED VERSION"""
        results = []
        
        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue
            
            matches = rule.match(data)
            
            for match in matches:
                result = {
                    'rule_name': rule_name,
                    'yara_rule': match.rule,
                    'match_length': len(data),
                    'strings': [],
                    'meta': match.meta,
                    'tags': match.tags,
                    'timestamp': datetime.now().isoformat(),
                    'source_info': source_info or {}
                }
                
                # Extract matched strings with their positions - FIXED
                for string in match.strings:
                    string_info = {
                        'identifier': string.identifier,
                        'instances': []
                    }
                    
                    for instance in string.instances:
                        # Get context around the match
                        start = max(0, instance.offset - 20)
                        
                        # FIX: Calculate length safely for YARA compatibility
                        try:
                            # Try to get length attribute (newer YARA versions)
                            match_length = getattr(instance, 'length', None)
                            if match_length is None:
                                # Fallback: estimate length from string identifier
                                match_length = len(string.identifier) if hasattr(string, 'identifier') else 20
                        except:
                            # Emergency fallback
                            match_length = 20
                        
                        end = min(len(data), instance.offset + match_length + 20)
                        context = data[start:end]
                        
                        # Extract matched data safely
                        try:
                            matched_data = data[instance.offset:instance.offset + match_length]
                        except:
                            # Fallback - get some data around the offset
                            matched_data = data[max(0, instance.offset):min(len(data), instance.offset + 20)]
                        
                        string_info['instances'].append({
                            'offset': instance.offset,
                            'length': match_length,
                            'matched_data': matched_data.hex() if matched_data else '',
                            'context': context.hex() if context else ''
                        })
                    
                    result['strings'].append(string_info)
                
                results.append(result)
                self.total_matches += 1
        
        return results
    
    def scan_packet(self, packet_info: Dict[str, Any], raw_data: bytes) -> List[Dict[str, Any]]:
        """Scan a network packet with YARA rules"""
        source_info = {
            'packet_id': packet_info.get('id'),
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('protocol'),
            'size': packet_info.get('size'),
            'timestamp': packet_info.get('timestamp')
        }
        
        return self.scan_data(raw_data, source_info)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get YARA engine statistics"""
        enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
        disabled_rules = len(self.rules) - enabled_rules
        
        rule_stats = []
        for name, rule in self.rules.items():
            rule_stats.append({
                'name': name,
                'enabled': rule.enabled,
                'match_count': rule.match_count,
                'last_match': rule.last_match.isoformat() if rule.last_match else None
            })
        
        return {
            'total_rules': len(self.rules),
            'enabled_rules': enabled_rules,
            'disabled_rules': disabled_rules,
            'total_matches': self.total_matches,
            'rule_details': rule_stats
        }

class YARAIDSRule:
    """YARA-based IDS rule that integrates with the existing IDS system"""
    
    def __init__(self, yara_engine: YARAEngine):
        self.name = "YARA Pattern Detection"
        self.description = "YARA rule-based pattern matching and malware detection"
        self.severity = "High"
        self.enabled = True
        self.trigger_count = 0
        self.yara_engine = yara_engine
    
    def check(self, packet_info: Dict[str, Any], raw_data: bytes = None) -> bool:
        """Check packet against YARA rules"""
        if not raw_data or len(raw_data) < 50:  # Skip very small packets
            return False
        
        # Skip very large packets for performance
        if len(raw_data) > 10000:  # Skip packets larger than 10KB
            return False
        
        try:
            # Scan with YARA engine
            yara_matches = self.yara_engine.scan_packet(packet_info, raw_data)
            
            if yara_matches:
                # Store detailed match information for alert generation
                packet_info['yara_matches'] = yara_matches
                return True
        except Exception as e:
            print(f"❌ YARA scanning error: {e}")
        
        return False
    
    def get_alert_message(self, packet_info: Dict[str, Any]) -> str:
        """Get detailed alert message for YARA matches"""
        yara_matches = packet_info.get('yara_matches', [])
        
        if not yara_matches:
            return f"{self.name}: {self.description}"
        
        # Get the first match for the alert message
        first_match = yara_matches[0]
        rule_name = first_match['yara_rule']
        
        message = f"YARA Detection: {rule_name}"
        
        if len(yara_matches) > 1:
            message += f" (+{len(yara_matches)-1} more rules)"
        
        return message

# Integration functions for the existing IDS

def integrate_yara_into_ids(ids_engine):
    """Integrate YARA engine into existing IDS"""
    
    # Initialize YARA engine
    yara_engine = YARAEngine()
    
    # Create YARA-based IDS rule
    yara_ids_rule = YARAIDSRule(yara_engine)
    
    # Add to existing IDS engine
    ids_engine.add_rule(yara_ids_rule)
    
    # Store reference to YARA engine for web interface
    ids_engine.yara_engine = yara_engine
    
    print("🔍 YARA engine integrated into IDS successfully!")
    return yara_engine

def create_enhanced_alert(original_alert: Dict[str, Any], yara_matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create enhanced alert with YARA match details"""
    
    enhanced_alert = original_alert.copy()
    
    # Add YARA-specific information
    enhanced_alert['yara_matches'] = yara_matches
    enhanced_alert['detection_type'] = 'YARA'
    enhanced_alert['matched_rules'] = [match['yara_rule'] for match in yara_matches]
    enhanced_alert['match_count'] = len(yara_matches)
    
    # Enhance description with YARA details
    if yara_matches:
        rule_names = ', '.join(set(match['yara_rule'] for match in yara_matches))
        enhanced_alert['description'] += f" | YARA Rules: {rule_names}"
    
    return enhanced_alert

# Example usage and testing
if __name__ == "__main__":
    print("🔍 YARA IDS Integration Test")
    print("=" * 50)
    
    # Initialize YARA engine
    yara_engine = YARAEngine()
    
    # Test with sample malicious data
    test_data = [
        b"<script>alert('xss')</script>",
        b"' OR '1'='1' --",
        b"cmd.exe /c whoami",
        b"SELECT * FROM users WHERE id = 1",
        b"Normal HTTP GET / request data"
    ]
    
    for i, data in enumerate(test_data, 1):
        print(f"\n🧪 Test {i}: {data[:50]}...")
        
        # Create fake packet info
        packet_info = {
            'id': i,
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'src_port': 12345,
            'dst_port': 80,
            'size': len(data)
        }
        
        # Scan with YARA
        matches = yara_engine.scan_packet(packet_info, data)
        
        if matches:
            print(f"🚨 DETECTED: {len(matches)} YARA matches")
            for match in matches:
                print(f"   Rule: {match['yara_rule']}")
                print(f"   Meta: {match['meta']}")
        else:
            print("✅ Clean - no matches")
    
    # Print statistics
    print("\n📊 YARA Engine Statistics:")
    stats = yara_engine.get_statistics()
    print(f"Total rules: {stats['total_rules']}")
    print(f"Enabled rules: {stats['enabled_rules']}")
    print(f"Total matches: {stats['total_matches']}")