# ArpSpoof

This repository contains 2 implementations of the well-known Arp spoofing attack.

**arp_spoof.py**

Implementation is done from scratch by using raw sockets and constructing ARP packets manually.

To start the attack run:
```bash
python arp_spoof.py –t [Target IP] –g [Gateway IP] –f [IP forward]
```

**scapy_arp_spoof.py**

Implementation uses the Scapy library to send and receive ARP packets. This version is created for comparison purpouses only. 
