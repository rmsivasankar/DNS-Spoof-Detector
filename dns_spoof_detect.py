import time
import threading
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from colorama import Fore, Style, init

init()

class DNSSpoofDetector:
    def __init__(self):
        self.trusted_dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.known_good = {}  # Cache of known good DNS responses
        self.log_file = "dns_spoof_log.txt"
        self.running = True

    def log_alert(self, message):
        with open(self.log_file, "a") as f:
            f.write(f"{time.ctime()}: {message}\n")
        print(f"{Fore.RED}[ALERT] {message}{Style.RESET_ALL}")

    def dns_query(self, domain, dns_server):
        try:
            packet = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
            response = sr1(packet, verbose=0, timeout=2)
            if response and response.haslayer(DNS):
                return [answer.rdata for answer in response[DNS].an if answer.type == 1]
        except Exception:
            return None
        return None

    def validate_response(self, domain, response_ip):
        # Check if we have a cached valid response
        if domain in self.known_good:
            return response_ip in self.known_good[domain]
        
        # Get responses from trusted servers
        trusted_ips = set()
        for server in self.trusted_dns_servers:
            ips = self.dns_query(domain, server)
            if ips:
                trusted_ips.update(ips)
                time.sleep(0.1)  # Small delay between queries
        
        if not trusted_ips:
            return True  # Can't verify, assume valid
        
        # Cache the trusted IPs
        self.known_good[domain] = trusted_ips
        
        return response_ip in trusted_ips

    def process_packet(self, packet):
        try:
            if packet.haslayer(DNS) and packet.haslayer(DNSRR) and packet[DNS].qr == 1:
                dns = packet[DNS]
                query = dns.qd.qname.decode('utf-8').rstrip('.') if dns.qd else None
                
                if not query or query in ['localhost', 'localdomain']:
                    return
                
                # Extract all A record responses
                response_ips = [answer.rdata for answer in dns.an if answer.type == 1]
                
                if not response_ips:
                    return
                
                # Validate each IP in the response
                for ip in response_ips:
                    if not self.validate_response(query, ip):
                        self.log_alert(
                            f"DNS Spoofing detected!\n"
                            f"Domain: {query}\n"
                            f"Suspicious IP: {ip}\n"
                            f"Expected IPs: {', '.join(self.known_good.get(query, ['Unknown']))}\n"
                            f"From: {packet[IP].src if packet.haslayer(IP) else 'Unknown'}"
                        )
                        break  # Only alert once per suspicious response
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Packet processing error: {e}{Style.RESET_ALL}")

    def start_sniffing(self):
        print(f"{Fore.CYAN}[*] Starting DNS monitoring...{Style.RESET_ALL}")
        while self.running:
            try:
                sniff(filter="udp port 53", prn=self.process_packet, store=0, timeout=5)
            except scapy.error.Scapy_Exception as e:
                if "Layer [IP] not found" in str(e):
                    continue  # Skip malformed packets
                print(f"{Fore.YELLOW}[WARNING] Sniffing error: {e}{Style.RESET_ALL}")
                time.sleep(1)

    def stop(self):
        self.running = False

def main():
    try:
        detector = DNSSpoofDetector()
        
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(target=detector.start_sniffing, daemon=True)
        sniff_thread.start()
        
        print(f"{Fore.GREEN}[*] DNS Spoof Detector running. Press Ctrl+C to stop.{Style.RESET_ALL}")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        detector.stop()
        print(f"{Fore.YELLOW}\n[*] Stopping DNS Spoof Detector...{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Fatal error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()