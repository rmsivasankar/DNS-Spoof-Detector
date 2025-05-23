from scapy.all import sniff
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP
from utils import network_utils
from responses.alert_system import AlertSystem
from utils.config_loader import get_trusted_servers


class DNSSniffer:
    def __init__(self):
        self.trusted_servers = get_trusted_servers()
        self.alert_system = AlertSystem()
    
    def start_sniffing(self):
        """Start sniffing DNS traffic"""
        sniff(filter="udp port 53", prn=self._process_packet, store=0)
    
    def _process_packet(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSRR):
            dns = packet[DNS]
            if dns.an and dns.qr:  # It's a response with answers
                query = dns.qd.qname.decode('utf-8') if dns.qd else "unknown"
                dns_server_ip = packet[IP].src
                
                # Query trusted servers for comparison
                trusted_answers = set()
                for trusted_server in self.trusted_servers[:2]:  # Check first 2 for speed
                    answers = network_utils.dns_query(query, trusted_server)
                    if answers:
                        trusted_answers.update(answers)
                
                if not trusted_answers:
                    return
                
                # Get answers from this response
                response_answers = set()
                for i in range(dns.ancount):
                    answer = dns.an[i]
                    if answer.type == 1:  # A record
                        response_answers.add(answer.rdata)
                
                # Check if any response IPs don't match trusted IPs
                if response_answers and not response_answers.intersection(trusted_answers):
                    self.alert_system.trigger_traffic_alert(query, dns_server_ip, response_answers, trusted_answers)