Files:
|- network_traffic_logger.py - (lightweight network traffic logger built with Scapy that tracks active network flows, packet counts, and bandwidth usage; designed for use on a Raspberry Pi)


Features:
|- Periodic export to JSONL (newline-delimited json)
|- Terminal display of active flows
|- Real-time view of active network flows
|- Packet and byte counting per flow


What is a flow:
|- A flow is a 5-tuple containing the source IP, destination IP, source port, destination port, and protocol being used (TCP/UDP).
|- Flows are normalized bidirectionally ((A -> B) == (A <- B)), so that one flow represents both directions of traffic


Terminal Output:
|- Displays active flows in real time
|- Includes:
    * Source and Destination IPs
    * Ports
    * Protocol 
    * Bytes transferred
    * Packet counts


JSONL Export:
|- Logs are written to "network_stats.jsonl" (a newline-delimted JSON)
|- Each line contains a snapshot of the total network state (including expired flows) at a given time


Requirements:
|- Python 3
|- Root privileges (required for packet capture, granted through sudo call)
|- Scapy


How to install dependencies:
|- pip install scapy


Finding your network interface:
|- The interface you choose will determine what traffic is visible to the program
|- To list available interfaces: ip a 
|- Common interfaces: 
    * eth0 (Ethernet) - Use when devices on your network are plugged into Ethernet
    * wlan0 (Wi-Fi) - Use when using Wi-Fi AP mode
    * br0 (Bridge) - Use if routing between interfaces
|- To confirm which interface carries your traffic:
    * sudo tcpdump -i {interface} (e.g. sudo tcpdump -i eth0)


How to Run:
|- sudo python3 network_traffic_logger.py
|- Script will prompt for a network interface


