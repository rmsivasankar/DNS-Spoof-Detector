import time
from colorama import Fore, Style, init
from utils.config_loader import get_log_file

init()

class Logger:
    def __init__(self, log_file=None):
        self.log_file = log_file or get_log_file()
    
    def log_alert(self, message):
        """Log alerts to a file"""
        timestamp = time.ctime()
        with open(self.log_file, "a") as f:
            f.write(f"{timestamp}: {message}\n")
    
    def print_info(self, message):
        print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}")
    
    def print_warning(self, message):
        print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
    
    def print_error(self, message):
        print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
    
    def print_success(self, message):
        print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")