import os
import subprocess
from ..utils.logging_utils import Logger

class Countermeasures:
    def __init__(self):
        self.logger = Logger()
    
    def flush_dns_cache(self):
        """Flush the local DNS cache"""
        try:
            subprocess.run(["ipconfig", "/flushdns"], check=True)
            self.logger.print_info("DNS cache flushed successfully")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.print_error(f"Failed to flush DNS cache: {e}")
            return False
    
    def block_malicious_server(self, ip_address):
        """Block a malicious DNS server using Windows Firewall"""
        try:
            # Create firewall rule to block the IP
            rule_name = f"Block_DNS_Spoofer_{ip_address}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip_address}",
                "protocol=UDP",
                "localport=53"
            ], check=True)
            
            self.logger.print_info(f"Successfully blocked malicious DNS server: {ip_address}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.print_error(f"Failed to block DNS server {ip_address}: {e}")
            return False