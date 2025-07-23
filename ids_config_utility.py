#!/usr/bin/env python3
"""
IDS Configuration Utility
Easy way to adjust detection sensitivity and reduce false positives
"""

import requests
import json
import time

class IDSConfigManager:
    def __init__(self, ids_url="http://localhost:5000"):
        self.ids_url = ids_url
        self.current_settings = {}
        
    def get_current_stats(self):
        """Get current IDS statistics"""
        try:
            # Get rules status
            rules_response = requests.get(f"{self.ids_url}/rules")
            rules_data = rules_response.json()
            
            # Get YARA stats
            yara_response = requests.get(f"{self.ids_url}/yara/stats")
            yara_data = yara_response.json()
            
            return {
                'rules': rules_data,
                'yara': yara_data,
                'timestamp': time.time()
            }
        except Exception as e:
            print(f"❌ Error getting stats: {e}")
            return None
    
    def display_current_settings(self):
        """Display current detection settings"""
        stats = self.get_current_stats()
        if not stats:
            print("❌ Unable to connect to IDS. Make sure it's running on http://localhost:5000")
            return
        
        print("=" * 60)
        print("📊 CURRENT IDS DETECTION SETTINGS")
        print("=" * 60)
        
        # Display traditional rules
        print("\n🛡️ Traditional Rules:")
        for rule in stats['rules']:
            if rule['type'] != 'Enhanced YARA Statistics':
                status = "✅ Enabled" if rule['enabled'] else "❌ Disabled"
                print(f"   • {rule['name']}: {status} (Triggers: {rule['trigger_count']})")
        
        # Display YARA settings
        if 'error' not in stats['yara']:
            yara = stats['yara']
            print(f"\n🔍 Enhanced YARA Settings:")
            print(f"   • Rules Active: {yara['enabled_rules']}/{yara['total_rules']}")
            print(f"   • Confidence Threshold: {yara['confidence_threshold']:.2f}")
            print(f"   • Total Matches: {yara['total_matches']}")
            print(f"   • False Positives Filtered: {yara['total_filtered']}")
            print(f"   • False Positive Rate: {yara['false_positives']}")
            
            # Calculate effectiveness
            if yara['total_matches'] + yara['total_filtered'] > 0:
                effectiveness = (yara['total_matches'] / (yara['total_matches'] + yara['total_filtered'])) * 100
                print(f"   • Detection Effectiveness: {effectiveness:.1f}%")
        else:
            print("\n🔍 Enhanced YARA: Not available")
        
        print("=" * 60)
    
    def adjust_yara_sensitivity(self, new_threshold):
        """Adjust YARA detection sensitivity"""
        try:
            response = requests.post(
                f"{self.ids_url}/yara/adjust_sensitivity",
                json={'threshold': new_threshold}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['success']:
                    print(f"✅ YARA sensitivity adjusted to {new_threshold}")
                    return True
                else:
                    print(f"❌ Failed: {result['message']}")
                    return False
            else:
                print(f"❌ HTTP Error: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error adjusting sensitivity: {e}")
            return False
    
    def recommend_settings(self):
        """Analyze current performance and recommend settings"""
        stats = self.get_current_stats()
        if not stats or 'error' in stats['yara']:
            print("❌ Cannot analyze - YARA statistics not available")
            return
        
        yara = stats['yara']
        total_detections = yara['total_matches'] + yara['total_filtered']
        
        print("\n🎯 SENSITIVITY RECOMMENDATIONS")
        print("=" * 50)
        
        if total_detections == 0:
            print("📊 No detections yet - current settings unchanged")
            print("💡 Run some traffic through your system first")
            return
        
        fp_rate = yara['total_filtered'] / total_detections if total_detections > 0 else 0
        current_threshold = yara['confidence_threshold']
        
        print(f"📊 Current Analysis:")
        print(f"   • Total Detections: {total_detections}")
        print(f"   • Valid Alerts: {yara['total_matches']}")
        print(f"   • Filtered (Potential FP): {yara['total_filtered']}")
        print(f"   • False Positive Rate: {fp_rate:.1%}")
        print(f"   • Current Threshold: {current_threshold:.2f}")
        
        # Recommendations based on performance
        if fp_rate > 0.7:  # High false positive rate
            recommended = min(0.95, current_threshold + 0.1)
            print(f"\n🔴 HIGH FALSE POSITIVE RATE ({fp_rate:.1%})")
            print(f"💡 Recommended: Increase threshold to {recommended:.2f}")
            print("   This will reduce false positives but may miss some threats")
        
        elif fp_rate > 0.4:  # Moderate false positive rate
            recommended = min(0.9, current_threshold + 0.05)
            print(f"\n🟡 MODERATE FALSE POSITIVE RATE ({fp_rate:.1%})")
            print(f"💡 Recommended: Slightly increase threshold to {recommended:.2f}")
        
        elif fp_rate < 0.1:  # Very low false positive rate
            if yara['total_matches'] < 5:  # But also very few detections
                recommended = max(0.5, current_threshold - 0.1)
                print(f"\n🟢 LOW FALSE POSITIVES ({fp_rate:.1%}) BUT FEW DETECTIONS")
                print(f"💡 Recommended: Decrease threshold to {recommended:.2f}")
                print("   This will increase sensitivity to catch more threats")
            else:
                print(f"\n🟢 OPTIMAL SETTINGS ({fp_rate:.1%} false positive rate)")
                print("💡 Current threshold appears well-tuned")
                recommended = current_threshold
        
        else:
            print(f"\n🟢 ACCEPTABLE FALSE POSITIVE RATE ({fp_rate:.1%})")
            print("💡 Current settings are reasonable")
            recommended = current_threshold
        
        if recommended != current_threshold:
            print(f"\n❓ Apply recommended threshold ({recommended:.2f})? (y/n): ", end="")
            choice = input().strip().lower()
            
            if choice == 'y':
                if self.adjust_yara_sensitivity(recommended):
                    print("✅ Settings updated successfully!")
                else:
                    print("❌ Failed to update settings")
    
    def interactive_tuning(self):
        """Interactive tuning session"""
        print("\n🎛️ INTERACTIVE SENSITIVITY TUNING")
        print("=" * 50)
        
        while True:
            self.display_current_settings()
            
            print("\n🔧 Tuning Options:")
            print("1. 🔴 Reduce False Positives (Increase threshold)")
            print("2. 🟡 Balanced Detection (Moderate threshold)")
            print("3. 🟢 Increase Sensitivity (Decrease threshold)")
            print("4. 🎯 Auto-Recommend Settings")
            print("5. 📊 Refresh Statistics")
            print("6. ❌ Exit")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == "1":
                print("\n🔴 Reducing false positives...")
                current_stats = self.get_current_stats()
                if current_stats and 'error' not in current_stats['yara']:
                    current = current_stats['yara']['confidence_threshold']
                    new_threshold = min(0.95, current + 0.1)
                    self.adjust_yara_sensitivity(new_threshold)
            
            elif choice == "2":
                print("\n🟡 Setting balanced detection...")
                self.adjust_yara_sensitivity(0.7)
            
            elif choice == "3":
                print("\n🟢 Increasing sensitivity...")
                current_stats = self.get_current_stats()
                if current_stats and 'error' not in current_stats['yara']:
                    current = current_stats['yara']['confidence_threshold']
                    new_threshold = max(0.3, current - 0.1)
                    self.adjust_yara_sensitivity(new_threshold)
            
            elif choice == "4":
                self.recommend_settings()
            
            elif choice == "5":
                print("🔄 Refreshing statistics...")
                continue
            
            elif choice == "6":
                print("👋 Exiting configuration utility")
                break
            
            else:
                print("❌ Invalid choice, please try again")
            
            if choice in ["1", "2", "3", "4"]:
                print("\n⏳ Waiting 2 seconds for settings to take effect...")
                time.sleep(2)
    
    def export_settings(self, filename="ids_settings.json"):
        """Export current settings to file"""
        stats = self.get_current_stats()
        if stats:
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            print(f"✅ Settings exported to {filename}")
        else:
            print("❌ Failed to export settings")
    
    def monitor_performance(self, duration=60):
        """Monitor detection performance for specified duration"""
        print(f"\n📊 MONITORING PERFORMANCE FOR {duration} SECONDS")
        print("=" * 50)
        
        initial_stats = self.get_current_stats()
        if not initial_stats:
            print("❌ Cannot start monitoring - IDS not accessible")
            return
        
        print(f"🕐 Starting monitoring at {time.strftime('%H:%M:%S')}")
        print("   Watching for detections and false positives...")
        
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                time.sleep(5)  # Check every 5 seconds
                
                current_stats = self.get_current_stats()
                if current_stats and 'error' not in current_stats['yara']:
                    yara = current_stats['yara']
                    initial_yara = initial_stats['yara']
                    
                    new_matches = yara['total_matches'] - initial_yara['total_matches']
                    new_filtered = yara['total_filtered'] - initial_yara['total_filtered']
                    
                    if new_matches > 0 or new_filtered > 0:
                        elapsed = int(time.time() - start_time)
                        print(f"📈 [{elapsed:02d}s] New alerts: {new_matches}, Filtered: {new_filtered}")
        
        except KeyboardInterrupt:
            print("\n⚠️ Monitoring interrupted by user")
        
        # Final report
        final_stats = self.get_current_stats()
        if final_stats and 'error' not in final_stats['yara']:
            final_yara = final_stats['yara']
            initial_yara = initial_stats['yara']
            
            total_new_matches = final_yara['total_matches'] - initial_yara['total_matches']
            total_new_filtered = final_yara['total_filtered'] - initial_yara['total_filtered']
            
            print(f"\n📊 MONITORING SUMMARY ({duration}s)")
            print(f"   • New Valid Alerts: {total_new_matches}")
            print(f"   • New Filtered (FP): {total_new_filtered}")
            print(f"   • Detection Rate: {total_new_matches/duration*60:.1f} alerts/minute")
            
            if total_new_matches + total_new_filtered > 0:
                fp_rate = total_new_filtered / (total_new_matches + total_new_filtered)
                print(f"   • False Positive Rate: {fp_rate:.1%}")

def main():
    """Main configuration utility"""
    print("🛡️ IDS Configuration Utility - False Positive Reduction")
    print("=" * 60)
    
    config_manager = IDSConfigManager()
    
    print("📋 Main Menu:")
    print("1. 📊 View Current Settings")
    print("2. 🎛️ Interactive Tuning")
    print("3. 🎯 Auto-Recommend Settings")
    print("4. 📈 Monitor Performance")
    print("5. 💾 Export Settings")
    print("6. ❌ Exit")
    
    while True:
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == "1":
            config_manager.display_current_settings()
        
        elif choice == "2":
            config_manager.interactive_tuning()
        
        elif choice == "3":
            config_manager.recommend_settings()
        
        elif choice == "4":
            duration = input("Monitor duration in seconds (default 60): ").strip()
            try:
                duration = int(duration) if duration else 60
                config_manager.monitor_performance(duration)
            except ValueError:
                print("❌ Invalid duration, using default 60 seconds")
                config_manager.monitor_performance(60)
        
        elif choice == "5":
            filename = input("Export filename (default: ids_settings.json): ").strip()
            filename = filename if filename else "ids_settings.json"
            config_manager.export_settings(filename)
        
        elif choice == "6":
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice, please try again")

if __name__ == "__main__":
    main()