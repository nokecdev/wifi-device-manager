#!/usr/bin/env python3
# scan_scripts/arp_scan.py
import json
import socket
import subprocess
import time
import sys
from shutil import which
from scapy.all import conf, get_if_addr, get_if_hwaddr, srp, ARP, Ether

from backend.scan_scripts.tools.oui_loader import load_oui, lookup_oui

mapping = load_oui()

COMMON_PORTS = [22, 80, 139, 443, 445, 3389, 5353, 1900]

#Returns the local networks's default interface, ip and network.
def get_local_iface_and_network():
    try:
        gw = conf.route.route("0.0.0.0")[0]
    except:
        gw: None
    #conf.iface is default iface
    iface = conf.iface
    ip = get_if_addr(iface)

    parts = ip.split('.')
    parts[-1] = '0/24'
    network = '.'.join(parts)
    return iface, ip, network


def get_local_network():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    # if ip is 192.168.1.10 -> 192.168.1.0/24
    parts = ip.split('.')
    parts[-1] = '0/24'
    return '.'.join(parts)

def arp_scan(iface, network, timeout=2):
    conf.verb = 0 # Do not write logs to console
    #Creates an ethernet header and payload for target mac 
    #Broadcast ARP requests for given network
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)
    #Receives packets (srp = send/receive at layer2)
    ans, _ = srp(pkt, timeout=2, iface=iface)
    devices = []
    for snd, rcv in ans:
        #Following parameters also can be extract:
        # rcv.op = ARP op code (1=request, 2=reply) good for checking if reply comes back
        # rcv.pdst = ARP target IP (to whom the request has been sent)
        # rcv.hwdst = ARP target MAC
        # Debug: rcv.summary(), rcv.show()

        #psrc = protocol source
        ip = rcv.psrc
        # hwsrc = hardware source
        mac = rcv.hwsrc
        devices.append({"ip": ip, "mac": mac})
    return devices

def reverse_dns(ip): 
    #returns host name or throws an exception if no name found 
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except Exception:
        return None
    
def tcp_probe(ip, port, timeout=1.0):
    try:
        # AF_INET = ipv4
        # AF_INET6 kell ipv6-hoz
        # SOCK_STREAM = stream connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the given ip and port, 
            # if success returns true
            # Otherwise throws exception 
            s.settimeout(timeout) 
            s.connect((ip, port))
            # For further mapping, if this returns a banner, the device type can be extracted from it            try:
            try:
                banner = s.recv(1024).decode(errors='ignore').strip()
                return True, banner
            except socket.timeout:
                return True, None
            
    except Exception:
        return False


def infer_device_type(info):
    vendor = info.get("vendor", "").lower() if info.get("vendor") else ""
    open_ports = info.get("open_ports", [])

    if vendor and "rasberry" in vendor:
        return "iot (rasberry-pi)"
    if vendor and ("apple" in vendor or "samsung" in vendor):
        if 5353 in open_ports or 80 in open_ports:
            return "phone/tablet"
    if any(p in open_ports for p in (22, 3389, 139, 445)):
        return "pc/server"
    if 1900 in open_ports or 5353 in open_ports:
        return "iot"
    return "unkonw"

def perform_enchance_scan():
    iface, myip, network = get_local_iface_and_network()
    #ARP scan
    devices = arp_scan(iface, network)
    results = []
    for d in devices:
        ip = d.get("ip")
        mac = d.get("mac")
        name = reverse_dns(ip)
        vendor = lookup_oui(mac, mapping)
        
        open_ports = []
        for p in COMMON_PORTS:
            if tcp_probe(ip, p, timeout=0.6):
                open_ports.append(p)
        devinfo = {
            "ip": ip,
            "mac": mac,
            "name": name,
            "vendor": vendor,
            "open_ports": open_ports
        }
        devinfo["guessed_type"] = infer_device_type(devinfo)
        results.append(devinfo)

    return {"interface": iface, "myip": myip, "network": network, "devices": results}


def main():
    out = perform_enchance_scan()
    print(json.dumps(out, indent=None))

if __name__ == "__main__":
    main()
