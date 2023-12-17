# MITM Scripts

Python scripts for network security operations.

## Script 1: DNS Spoofing

### Description
- Script: `dns_spoof.py`
- Description: Performs DNS spoofing to redirect requests for a specific domain to a different IP address.

### Usage
- Run the script with Python 3 and appropriate permissions.
- Modify the `target` and `gateway` IP addresses within the script to match your environment.
- Execute the script: `sudo python3 dns_spoof.py`

## Script 2: ARP Spoofing

### Description
- Script: `arp_spoof.py`
- Description: Performs ARP spoofing between a target IP and gateway IP.

### Usage
- Run the script with Python 3 and appropriate permissions.
- Modify the `target_ip` and `gateway_ip` variables within the script to match your network setup.
- Execute the script: `sudo python3 arp_spoof.py`

## Script 3: Packet Sniffing

### Description
- Script: `packet_sniffer.py`
- Description: Sniffs network packets to extract URLs and potential login information.

### Usage
- Run the script with Python 3 and appropriate permissions.
- The script prompts for the network interface to sniff and optional filtering criteria.
- Execute the script: `sudo python3 packet_sniffer.py`

---

**Note**: Ensure you have the necessary permissions and authorization to run these scripts, as they involve manipulation of network traffic and might have security implications. Use responsibly and only in controlled environments.
