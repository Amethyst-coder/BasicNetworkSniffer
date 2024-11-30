# Network Sniffer

A Python-based network sniffer that captures and analyzes network traffic. This project provides a deeper understanding of how data flows through a network, how network packets are structured, and how to interpret packet details like Ethernet headers, IPv4 headers, and transport protocols (TCP, UDP, ICMP).

---

## Features

- *Packet Capturing*: Intercepts raw network packets on the interface.
- *Packet Decoding*: Decodes Ethernet, IPv4, ICMP, TCP, and UDP packets.
- *Protocol Analysis*: Identifies protocols and extracts key information.
- *Human-Readable Output*: Displays packet details in a structured and readable format.

---

## Requirements

- *Python 3.x*
- Administrative/root privileges (required for capturing raw packets)
- Operating System: Linux-based (tested on Ubuntu/Kali Linux; modify for Windows).

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/network-sniffer.git
   cd network-sniffer
