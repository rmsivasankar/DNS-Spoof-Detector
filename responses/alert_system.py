from utils.logging_utils import Logger

class AlertSystem:
    def __init__(self):
        self.logger = Logger()  # Now works with default log file
    
    def trigger_spoof_alert(self, domain, expected_ip, suspicious_servers, results):
        alert_msg = f"Possible DNS spoofing detected!\n" \
                   f"Domain: {domain}\n" \
                   f"Expected IP: {expected_ip}\n" \
                   f"Suspicious servers: {', '.join(suspicious_servers)}\n" \
                   f"Responses from suspicious servers:\n"
        
        for server in suspicious_servers:
            alert_msg += f"  - {server}: {', '.join(results[server])}\n"
        
        self.logger.log_alert(alert_msg)
        self.logger.print_error(alert_msg)
        
    def trigger_traffic_alert(self, query, dns_server, received_ips, trusted_ips):
        alert_msg = f"Possible DNS spoofing in network traffic!\n" \
                   f"Query: {query}\n" \
                   f"DNS Server: {dns_server}\n" \
                   f"Received IPs: {', '.join(received_ips)}\n" \
                   f"Trusted IPs: {', '.join(trusted_ips)}\n"
        
        self.logger.log_alert(alert_msg)
        self.logger.print_error(alert_msg)
    
    def log_error(self, message):
        self.logger.log_alert(message)
        self.logger.print_error(message)
    
    def log_success(self, message):
        self.logger.print_success(message)