"""
Packet Sniffer Class
Refactored from original by Luis Fernando Javier Velazquez
"""

import binascii
import socket
import struct
import threading
from collections import deque
from datetime import datetime


class PacketSniffer:
    def __init__(self, max_history=200):
        self.max_history = max_history
        self.packet_history = deque(maxlen=max_history)
        self.running = False
        self.lock = threading.Lock()

        # Packet callback function
        self.on_packet = None

        # Counters
        self.counters = {
            "ethernet": {"ip": 0, "arp": 0, "others": 0},
            "ip": {"tcp": 0, "udp": 0, "icmp": 0, "others": 0},
            "application": {
                "http": 0,
                "ssh": 0,
                "dns": 0,
                "smtp": 0,
                "https": 0,
                "others": 0,
            },
            "ip_version": {"ipv4": 0, "ipv6": 0},
        }

        # For packets per second tracking
        self.packets_per_second = 0
        self._packet_count_this_second = 0

    def get_stats(self):
        """Return current statistics."""
        with self.lock:
            total = (
                self.counters["ethernet"]["ip"]
                + self.counters["ethernet"]["arp"]
                + self.counters["ethernet"]["others"]
                + self.counters["ip_version"]["ipv6"]
            )
            return {
                "total": total,
                "counters": self.counters.copy(),
                "packets_per_second": self.packets_per_second,
            }

    def get_history(self):
        """Return packet history."""
        with self.lock:
            return list(self.packet_history)

    def _format_mac(self, mac_bytes):
        """Format MAC address bytes to string."""
        mac_hex = binascii.hexlify(mac_bytes).decode("ascii")
        return ":".join(mac_hex[i : i + 2] for i in range(0, 12, 2))

    def _format_ip(self, ip_bytes):
        """Format IP address bytes to string."""
        return ".".join(str(b) for b in ip_bytes)

    def _process_udp(self, raw_data, packet_info):
        """Process UDP packet."""
        self.counters["ip"]["udp"] += 1
        packet_info["transport"] = "UDP"

        if len(raw_data) >= 42:
            udp_header = struct.unpack("!HHHH", raw_data[34:42])
            src_port = udp_header[0]
            dst_port = udp_header[1]
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port

            if src_port == 53 or dst_port == 53:
                self.counters["application"]["dns"] += 1
                packet_info["application"] = "DNS"
            else:
                self.counters["application"]["others"] += 1
                packet_info["application"] = "Other"

    def _process_tcp(self, raw_data, packet_info):
        """Process TCP packet."""
        self.counters["ip"]["tcp"] += 1
        packet_info["transport"] = "TCP"

        if len(raw_data) >= 54:
            tcp_header = struct.unpack("!HHLLBBHHH", raw_data[34:54])
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port

            if src_port == 80 or dst_port == 80:
                self.counters["application"]["http"] += 1
                packet_info["application"] = "HTTP"
            elif src_port == 22 or dst_port == 22:
                self.counters["application"]["ssh"] += 1
                packet_info["application"] = "SSH"
            elif src_port == 25 or dst_port == 25:
                self.counters["application"]["smtp"] += 1
                packet_info["application"] = "SMTP"
            elif src_port == 443 or dst_port == 443:
                self.counters["application"]["https"] += 1
                packet_info["application"] = "HTTPS"
            else:
                self.counters["application"]["others"] += 1
                packet_info["application"] = "Other"

    def _process_ip(self, raw_data, packet_info):
        """Process IP packet."""
        self.counters["ip_version"]["ipv4"] += 1
        self.counters["ethernet"]["ip"] += 1
        packet_info["type"] = "IPv4"

        if len(raw_data) >= 34:
            ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[14:34])
            protocol = ip_header[6]
            packet_info["src_ip"] = self._format_ip(ip_header[8])
            packet_info["dst_ip"] = self._format_ip(ip_header[9])

            if protocol == 6:
                self._process_tcp(raw_data, packet_info)
            elif protocol == 17:
                self._process_udp(raw_data, packet_info)
            elif protocol == 1:
                self.counters["ip"]["icmp"] += 1
                packet_info["transport"] = "ICMP"
            else:
                self.counters["ip"]["others"] += 1
                packet_info["transport"] = "Other"

    def _process_packet(self, raw_data):
        """Process a captured packet."""
        packet_info = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "size": len(raw_data),
            "type": "Unknown",
            "src_mac": "",
            "dst_mac": "",
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "transport": "",
            "application": "",
        }

        if len(raw_data) >= 14:
            eth_header = struct.unpack("!6s6sH", raw_data[0:14])
            packet_info["dst_mac"] = self._format_mac(eth_header[0])
            packet_info["src_mac"] = self._format_mac(eth_header[1])
            proto_type = eth_header[2]
            next_proto = hex(proto_type)

            if next_proto == "0x800":
                self._process_ip(raw_data, packet_info)
            elif next_proto == "0x806":
                self.counters["ethernet"]["arp"] += 1
                packet_info["type"] = "ARP"
            elif next_proto == "0x86dd":
                self.counters["ip_version"]["ipv6"] += 1
                packet_info["type"] = "IPv6"
            else:
                self.counters["ethernet"]["others"] += 1
                packet_info["type"] = "Other"

        with self.lock:
            self.packet_history.append(packet_info)
            self._packet_count_this_second += 1

        # Call the callback if set
        if self.on_packet:
            self.on_packet(packet_info)

    def _update_pps(self):
        """Update packets per second counter."""
        with self.lock:
            self.packets_per_second = self._packet_count_this_second
            self._packet_count_this_second = 0

    def start(self):
        """Start packet capture."""
        self.running = True
        raw_socket = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3)
        )

        # PPS update timer
        def pps_timer():
            while self.running:
                threading.Event().wait(1.0)
                self._update_pps()

        pps_thread = threading.Thread(target=pps_timer, daemon=True)
        pps_thread.start()

        while self.running:
            try:
                raw_data, addr = raw_socket.recvfrom(65536)
                self._process_packet(raw_data)
            except Exception as e:
                if self.running:
                    print(f"Error capturing packet: {e}")

    def stop(self):
        """Stop packet capture."""
        self.running = False