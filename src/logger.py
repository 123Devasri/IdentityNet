import os
import sys
import time
import threading
from datetime import datetime

class TrafficLogger:
    """
    Thread-safe Logging Engine for IdentityNet Firewall.
    Logs network decisions to logs/traffic.log and formats live console output.
    """
    def __init__(self, log_file_path="logs/traffic.log", verbose=True):
        self.log_file_path = os.path.abspath(log_file_path)
        self.verbose = verbose
        self.lock = threading.Lock()
        
        # Ensure log directory exists
        log_dir = os.path.dirname(self.log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        # Initialize log file header if new
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write("# IdentityNet Traffic Log\n")
                f.write("# Format: Timestamp | User | Source IP | Destination IP | Domain | Protocol | Action | Reason\n")
                f.write("=" * 110 + "\n")

    def log_traffic(self, user: str, src_ip: str, dst_ip: str, domain: str, protocol: str, action: str, reason: str = ""):
        """
        Log network traffic event to file and console.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] | User: {user:<14} | Src: {src_ip:<15} | Dst: {dst_ip:<15} | Domain: {domain:<20} | Proto: {protocol:<8} | Action: {action:<5} | Reason: {reason}\n"
        
        with self.lock:
            # Write to traffic.log
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(log_entry)
            
            # Print formatted log to console
            if self.verbose:
                if action.upper() == "ALLOW":
                    action_fmt = "\033[92mALLOW\033[0m"  # Green
                else:
                    action_fmt = "\033[91mBLOCK\033[0m"  # Red
                    
                console_msg = (
                    f"[{timestamp}] [\033[94m{user}\033[0m] {src_ip} -> {dst_ip} ({domain}) "
                    f"[{protocol}] => {action_fmt} ({reason})"
                )
                print(console_msg, flush=True)

    def log_system(self, level: str, message: str):
        """
        Log internal system events (startup, routing, firewall rules).
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix_color = "\033[93m" if level == "WARN" else "\033[96m"
        formatted_msg = f"[{timestamp}] [{prefix_color}{level}\033[0m] {message}"
        
        with self.lock:
            print(formatted_msg, flush=True)
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [SYSTEM:{level}] {message}\n")
