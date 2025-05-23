import requests
from utils.config_loader import load_config  # Changed from relative to absolute import

class DomainManager:
    def __init__(self):
        self.config = load_config()
    
    def get_common_domains(self):
        """Get a list of common domains to monitor"""
        try:
            response = requests.get("https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt", timeout=5)
            if response.status_code == 200:
                return [line.strip() for line in response.text.split('\n') if line.strip() and not line.startswith('#')][:50]
        except:
            pass
        
        # Fallback to config or default list
        return self.config.get('monitored_domains', [
            "google.com",
            "facebook.com",
            "youtube.com",
            "amazon.com",
            "twitter.com"
        ])