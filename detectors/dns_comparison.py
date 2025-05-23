from utils import network_utils
from utils.config_loader import get_trusted_servers
from responses.alert_system import AlertSystem


class DNSComparator:
    def __init__(self):
        self.trusted_servers = get_trusted_servers()
        self.alert_system = AlertSystem()
    
    def check_dns_spoofing(self, domain):
        """Check for DNS spoofing by comparing responses from different servers"""
        local_dns_servers = network_utils.get_local_dns_servers()
        all_servers = self.trusted_servers + local_dns_servers
        
        results = {}
        
        for server in all_servers:
            answers = network_utils.dns_query(domain, server)
            if answers:
                results[server] = answers
        
        if not results:
            self.alert_system.log_error(f"No DNS servers responded to the query for {domain}")
            return False
        
        # Get the most common answer
        all_answers = []
        for answers in results.values():
            all_answers.extend(answers)
        
        if not all_answers:
            return False
        
        # Find the most common IP
        answer_counts = {}
        for ip in all_answers:
            answer_counts[ip] = answer_counts.get(ip, 0) + 1
        
        most_common_ip = max(answer_counts.items(), key=lambda x: x[1])[0]
        
        # Check for servers that returned different answers
        suspicious_servers = []
        for server, answers in results.items():
            if most_common_ip not in answers:
                suspicious_servers.append(server)
        
        if suspicious_servers:
            self.alert_system.trigger_spoof_alert(domain, most_common_ip, suspicious_servers, results)
            return True
        
        self.alert_system.log_success(f"No DNS spoofing detected for {domain}")
        return False