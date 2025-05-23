import socket
import winreg
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

def get_local_dns_servers():
    """Get DNS servers configured on the local machine"""
    try:
        dns_servers = []
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces") as interfaces:
            for i in range(winreg.QueryInfoKey(interfaces)[0]):
                interface_key_name = winreg.EnumKey(interfaces, i)
                with winreg.OpenKey(interfaces, interface_key_name) as interface_key:
                    try:
                        nameserver, _ = winreg.QueryValueEx(interface_key, "NameServer")
                        if nameserver and nameserver.strip():
                            dns_servers.extend([s.strip() for s in nameserver.split(',') if s.strip()])
                    except WindowsError:
                        continue
        return list(set(dns_servers))  # Remove duplicates
    except Exception as e:
        print(f"[WARNING] Could not retrieve local DNS servers: {e}")
        return []

def dns_query(domain, dns_server):
    """Send a DNS query to a specific DNS server"""
    try:
        dns_packet = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        response = sr1(dns_packet, verbose=0, timeout=2)
        
        if response and response.haslayer(DNS):
            answers = []
            for i in range(response[DNS].ancount):
                answer = response[DNS].an[i]
                if answer.type == 1:  # A record
                    answers.append(answer.rdata)
            return answers if answers else None
    except Exception as e:
        print(f"[WARNING] DNS query to {dns_server} failed: {e}")
    return None