import nmap
from scapy.all import ARP, Ether, srp

# Test nmap
scanner = nmap.PortScanner()
scanner.scan(hosts="192.168.1.0/24", arguments="-sn")
print("nmap working:", scanner.all_hosts())

# Test scapy
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.1/24")
ans, _ = srp(pkt, timeout=2, verbose=False)
print("scapy working:", [rcv.psrc for _, rcv in ans])
