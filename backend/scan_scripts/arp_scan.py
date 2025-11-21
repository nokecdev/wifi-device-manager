#!/usr/bin/env python3
# scan_scripts/arp_scan.py
import json
import socket
import subprocess
import time
import sys
import os
import platform
import re
from pathlib import Path
from shutil import which
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to Python path to allow imports
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent  # Go up from scan_scripts -> backend -> project root
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.scan_scripts.tools.oui_loader import load_oui, lookup_oui

mapping = load_oui()

COMMON_PORTS = [22, 80, 139, 443, 445, 3389, 5353, 1900]

IS_WINDOWS = platform.system() == "Windows"

# Only import scapy on non-Windows or if available
if not IS_WINDOWS:
    try:
        from scapy.all import conf, get_if_addr, get_if_hwaddr, srp, ARP, Ether
        SCAPY_AVAILABLE = True
    except ImportError:
        SCAPY_AVAILABLE = False
else:
    SCAPY_AVAILABLE = False

#Returns the local networks's default interface, ip and network.
def get_local_iface_and_network():
    if IS_WINDOWS or not SCAPY_AVAILABLE:
        # Windows fallback: use socket to get local IP
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        # Try to get default gateway interface
        try:
            result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                  capture_output=True, text=True, timeout=2)
            # Parse interface name from route output
            iface = "Unknown"
        except:
            iface = "Unknown"
    else:
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

def arp_scan_windows(network, timeout=2):
    """Windows-compatible ARP scan using arp -a command and ping sweep"""
    devices = []
    
    # Get ARP table entries
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        arp_output = result.stdout
        
        # Parse ARP table: format is "192.168.1.1   00-11-22-33-44-55   dynamic"
        arp_pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})'
        matches = re.findall(arp_pattern, arp_output)
        
        arp_dict = {}
        for ip, mac in matches:
            # Normalize MAC address format
            mac = mac.replace('-', ':').lower()
            arp_dict[ip] = mac
    except Exception as e:
        arp_dict = {}
    
    # Extract network base (e.g., 192.168.1.0/24 -> 192.168.1)
    network_base = network.split('/')[0]
    base_parts = network_base.split('.')
    base_ip = '.'.join(base_parts[:3])
    
    # Ping sweep to discover active devices
    def ping_host(host_num):
        ip = f"{base_ip}.{host_num}"
        try:
            # Windows ping: -n 1 = send 1 packet, -w 500 = timeout 500ms
            result = subprocess.run(['ping', '-n', '1', '-w', '500', ip], 
                                  capture_output=True, timeout=1)
            if result.returncode == 0:
                mac = arp_dict.get(ip)
                if mac:
                    return {"ip": ip, "mac": mac}
                else:
                    # Device responded but not in ARP table yet, try to get MAC
                    return {"ip": ip, "mac": None}
        except:
            pass
        return None
    
    # Scan common IPs (1-254) with limited concurrency
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping_host, i) for i in range(1, 255)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                devices.append(result)
    
    return devices

def arp_scan(iface, network, timeout=2):
    if IS_WINDOWS or not SCAPY_AVAILABLE:
        return arp_scan_windows(network, timeout)
    
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
            # For further mapping, if this returns a banner, the device type can be extracted from it
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
        
        # Only lookup vendor if MAC address is available
        vendor = lookup_oui(mac, mapping) if mac else None
        
        open_ports = []
        for p in COMMON_PORTS:
            result = tcp_probe(ip, p, timeout=0.6)
            if result:  # result is either False or (True, banner)
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
