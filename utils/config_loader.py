import yaml
import os

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.yaml')
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def get_trusted_servers():
    config = load_config()
    return config.get('trusted_dns_servers', [])

def get_check_interval():
    config = load_config()
    return config.get('check_interval', 300)

def get_log_file():
    config = load_config()
    return config.get('log_file', 'dns_spoof_log.txt')