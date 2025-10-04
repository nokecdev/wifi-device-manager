#!/usr/bin/env python3
# scan_scripts/arp_scan.py
import json
import socket
import subprocess
import sys
from scapy.all import ARP, Ether, srp, conf

def get_local_network():
    # Egyszerű, feltételezi /24 hálózatot — később bővítsd dinamikusan.
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    # ha az IP például 192.168.1.10 -> 192.168.1.0/24
    parts = ip.split('.')
    parts[-1] = '0/24'
    return '.'.join(parts)

def arp_scan(network):
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)
    ans, _ = srp(pkt, timeout=2)
    devices = []
    for snd, rcv in ans:
        ip = rcv.psrc
        mac = rcv.hwsrc
        # próbáljunk reverse DNS-t
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = None
        devices.append({"ip": ip, "mac": mac, "name": name})
    return devices

def main():
    network = get_local_network()
    devices = arp_scan(network)
    print(json.dumps({"network": network, "devices": devices}))

if __name__ == "__main__":
    main()
