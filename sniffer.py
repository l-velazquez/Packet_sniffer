import socket
import struct
import time
from collections import deque

# Shared Data
packet_data = {
    "ethernet": {"ip": 0, "arp": 0, "others": 0},
    "ip": {"tcp": 0, "udp": 0, "icmp": 0, "others": 0},
    "application": {"http": 0, "ssh": 0, "dns": 0, "smtp": 0, "https": 0, "others": 0},
    "ip_version": {"ipv4": 0, "ipv6": 0},
    "total": 0,
    "speed": 0  # Bytes per second
}

# Store last 10 packets for the UI table
# Each item: {'src': 'x', 'dst': 'y', 'proto': 'TCP', 'len': 100}
recent_packets = deque(maxlen=10)

# Helper to track speed
byte_count_1s = 0
last_time = time.time()

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr))

def process_packet(raw_socket):
    global byte_count_1s, last_time
    
    try:
        raw_data, addr = raw_socket.recvfrom(65536)
        
        # Speed Calculation
        current_time = time.time()
        byte_count_1s += len(raw_data)
        if current_time - last_time >= 1:
            packet_data["speed"] = byte_count_1s
            byte_count_1s = 0
            last_time = current_time

        packet_data["total"] += 1
        
        # Ethernet Header
        eth_header = struct.unpack("!6s6sH", raw_data[0:14])
        proto_type = eth_header[2]
        next_proto = hex(proto_type)

        packet_info = {
            "src": get_mac_addr(eth_header[1]),
            "dst": get_mac_addr(eth_header[0]),
            "proto": "ETH",
            "len": len(raw_data)
        }

        if next_proto == '0x800': # IPv4
            packet_data["ethernet"]["ip"] += 1
            packet_data["ip_version"]["ipv4"] += 1
            
            # IP Header extraction
            ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[14:34])
            protocol = ip_header[6]
            packet_info["src"] = socket.inet_ntoa(ip_header[8])
            packet_info["dst"] = socket.inet_ntoa(ip_header[9])

            if protocol == 6: # TCP
                packet_data["ip"]["tcp"] += 1
                packet_info["proto"] = "TCP"
                # Check ports for App Layer
                if len(raw_data) > 54:
                    tcp_header = struct.unpack("!HHLLBBHHH", raw_data[34:54])
                    src_port = tcp_header[0]
                    dst_port = tcp_header[1]
                    if src_port == 80 or dst_port == 80: 
                        packet_data["application"]["http"] += 1
                        packet_info["proto"] = "HTTP"
                    elif src_port == 443 or dst_port == 443: 
                        packet_data["application"]["https"] += 1
                        packet_info["proto"] = "HTTPS"
            
            elif protocol == 17: # UDP
                packet_data["ip"]["udp"] += 1
                packet_info["proto"] = "UDP"
                # Check DNS
                if len(raw_data) > 54:
                    udp_header = struct.unpack("!HHLLBBHHH", raw_data[34:54])
                    if udp_header[0] == 53 or udp_header[1] == 53:
                        packet_data["application"]["dns"] += 1
                        packet_info["proto"] = "DNS"

            elif protocol == 1: # ICMP
                packet_data["ip"]["icmp"] += 1
                packet_info["proto"] = "ICMP"

        elif next_proto == '0x806':
            packet_data["ethernet"]["arp"] += 1
            packet_info["proto"] = "ARP"
            
        elif next_proto == '0x86dd':
            packet_data["ip_version"]["ipv6"] += 1
            packet_info["proto"] = "IPv6"

        # Add to recent packets list
        recent_packets.appendleft(packet_info)

    except Exception:
        pass

def start_sniffing():
    try:
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Sniffer started...")
        while True:
            process_packet(raw_socket)
    except PermissionError:
        print("Error: Sudo required.")