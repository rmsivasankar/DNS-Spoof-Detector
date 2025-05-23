import time
import threading
import ctypes
import sys
import os
from colorama import Fore, Style, init
from detectors.dns_comparison import DNSComparator
from detectors.packet_sniffer import DNSSniffer
from detectors.domain_manager import DomainManager
from utils.config_loader import get_check_interval
from utils.logging_utils import Logger

init()

def check_admin_privileges():
    """Check if the script is running with admin privileges"""
    try:
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print(f"{Fore.RED}[ERROR] This tool requires administrator privileges.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please run the script as Administrator.{Style.RESET_ALL}")
            time.sleep(5)
            sys.exit(1)
        return True
    except:
        return True

def continuous_monitoring():
    """Continuously monitor DNS for spoofing"""
    logger = Logger()  # Now works with default log file from config
    comparator = DNSComparator()
    domain_manager = DomainManager()
    domains = domain_manager.get_common_domains()
    
    logger.print_info(f"Monitoring {len(domains)} domains for DNS spoofing")
    
    while True:
        for domain in domains:
            comparator.check_dns_spoofing(domain)
            time.sleep(1)
        
        logger.print_info(f"Waiting {get_check_interval()} seconds before next scan...")
        time.sleep(get_check_interval())

def main():
    print(f"{Fore.BLUE}\nDNS Spoof Detector for Windows{Style.RESET_ALL}")
    print(f"{Fore.CYAN}============================={Style.RESET_ALL}\n")
    
    if not check_admin_privileges():
        return
    
    try:
        monitor_thread = threading.Thread(target=continuous_monitoring, daemon=True)
        monitor_thread.start()
        
        sniffer = DNSSniffer()
        sniffer.start_sniffing()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[*] Stopping DNS Spoof Detector...{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Fatal error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()