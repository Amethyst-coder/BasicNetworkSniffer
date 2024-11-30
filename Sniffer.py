import socket
import struct
import textwrap
from datetime import datetime

# Utility functions
def format_multi_line(prefix, string, size=80):
    """Formats multi-line data output."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(f'{byte:02x}' for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def mac_address(bytes_addr):
    """Returns human-readable MAC address."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_address(addr):
    """Returns human-readable IPv4 address."""
    return '.'.join(map(str, addr))

# Protocol names for readability
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Packet processing functions
def ethernet_frame(data):
    """Unpack Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return mac_address(dest_mac), mac_address(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    """Unpack IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4_address(src), ipv4_address(target), data[header_length:]

def icmp_packet(data):
    """Unpack ICMP packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    """Unpack TCP segment."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    """Unpack UDP segment."""
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

# Main sniffing function
def sniff():
    """Sniffer that captures and displays network packets."""
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("Starting packet capture... Press Ctrl+C to stop.")
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print("\n[{}] Ethernet Frame:".format(timestamp))
            print("Destination MAC: {}, Source MAC: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

            # Handle IPv4 packets
            if eth_proto == 8:
                version, header_length, ttl, proto, src_ip, target_ip, data = ipv4_packet(data)
                proto_name = PROTOCOL_MAP.get(proto, "Unknown")
                print("\tIPv4 Packet:")
                print("\tVersion: {}, Header Length: {} Bytes, TTL: {}".format(version, header_length, ttl))
                print("\tProtocol: {}, Source IP: {}, Target IP: {}".format(proto_name, src_ip, target_ip))

                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print("\t\tICMP Packet:")
                    print("\t\tType: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                    print("\t\tData:\n{}".format(format_multi_line("\t\t\t", data)))

                elif proto == 6:  # TCP
                    src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                    print("\t\tTCP Segment:")
                    print("\t\tSource Port: {}, Destination Port: {}".format(src_port, dest_port))
                    print("\t\tSequence: {}, Acknowledgment: {}".format(sequence, acknowledgment))
                    print("\t\tFlags: {}".format(flags))
                    print("\t\tData:\n{}".format(format_multi_line("\t\t\t", data)))

                elif proto == 17:  # UDP
                    src_port, dest_port, length, data = udp_segment(data)
                    print("\t\tUDP Segment:")
                    print("\t\tSource Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port, length))
                    print("\t\tData:\n{}".format(format_multi_line("\t\t\t", data)))

                else:
                    print("\t\tOther Protocol Data:\n{}".format(format_multi_line("\t\t\t", data)))

            else:
                print("Non-IPv4 Protocol Data:\n{}".format(format_multi_line("\t", data)))
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

if _name_ == "_main_":
    sniff()
