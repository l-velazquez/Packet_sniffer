'''====================================================================

    Final Project
    CCOM 4205 - Computer Networking
    Title: Packet Sniffer
    Programmer: Luis Fernando Javier Velazquez
    Email: luisfernandojavier.velazquez@upr.edu
    Student Num.: 801-18-8580

    Description: This program is a packet sniffer. 
    It will run and will tell you what packages 
    from the network using a raw socket, and counts 
    the number of different types of protocols it 
    encounters. It counts the number of ARP packets, 
    IP packets, TCP packets, UDP packets, and different 
    types of application protocols (HTTP, SSH, DNS, 
    SMTP, and others) that it sees.



===================================================================='''


import binascii #binary data to a printable ASCII string
import socket 
import struct

debug = 0 #variable meant for debugging
screen_count = 1 #display the captured packages
# Counters for different protocols
# Dictionary data structure
counters = {
    "ethernet": {
        "ip": 0,
        "arp": 0,
        "others": 0
    },
    "ip": {
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "others": 0
    },
    "application": {
        "http": 0,
        "ssh": 0,
        "dns": 0,
        "smtp": 0,
        "https": 0,
        "others": 0
    },
    "ip_version":{
        "ipv4": 0,
        "ipv6": 0
    }
}

# When you hit Ctr+C this function will execute
def exit_gracefully():
    # Print the values of the counters
    total= counters["ethernet"]["ip"] + counters["ethernet"]["arp"] + counters["ethernet"]["others"]+counters["ip_version"]["ipv6"]
    print("\nThe packet sniffer processed a total of",total , "packets.")
    print("\nOf the", total, "packets:")
    print(counters["ethernet"]["arp"], "are ARP packets")
    print(counters["ethernet"]["ip"], "are IP packets")
    print("\t", counters["ethernet"]["others"], "are Other packets")
    print("\nOf the", counters["ethernet"]["ip"], "IP packets:")
    print(counters["ip"]["tcp"], "are TCP packets")
    print(counters["ip"]["udp"], "are UDP packets")
    print("\t", counters["ip"]["icmp"], "are ICMP packets")
    print("\t", counters["ip"]["others"], "are Other packets")
    print("\nOf the", counters["ip"]["tcp"] + counters["ip"]["udp"], "TCP and UDP packets:")
    print("\t", counters["application"]["http"], "are HTTP packets")
    print("\t", counters["application"]["ssh"], "are SSH packets")
    print("\t", counters["application"]["dns"], "are DNS packets")
    print("\t", counters["application"]["smtp"], "are SMTP packets")
    print("\t", counters["application"]["https"], "are HTTPS packets")
    print("\t", counters["application"]["others"], "are Other packets")
    print("\nOf total of",total,"packages:")
    print("\t",counters["ip_version"]["ipv4"],": IPV4,",counters["ip_version"]["ipv6"],": IPV6,",total - (counters["ip_version"]["ipv4"] + counters["ip_version"]["ipv6"]),": Other")
    print("\nThanks for using our simple sniffer. In python… :)")

def udp_proto(raw_data):
    counters["ip"]["udp"]+=1
    if debug:
        size_of_raw_data = len(raw_data[34:54])
        print(size_of_raw_data)
        # Some UDP packages observed (using raspberry pi) were length 9 bytes.
        # Don't know why but made a conditional to 
        # handle this exception.

    if len(raw_data[34:54]) == 20:
        udp_header = struct.unpack("!HHLLBBHHH",raw_data[34:54])
        src_port = udp_header[0]
        dst_port = udp_header[1]
        if debug:
            print("UDP header", udp_header)
            print("Source Port",src_port)
            print("Destination Port",dst_port)
        if src_port == 53 or dst_port == 53:
            # DNS packet
            counters["application"]["dns"] += 1

def ip_layer(raw_data):
    # IP packet
    counters["ip_version"]["ipv4"] += 1
    counters["ethernet"]["ip"] += 1

    # Extract the IP header
    ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[14:34])
    protocol = ip_header[6]
    if debug:
        print("Protocol",protocol)

    # Check the protocol in the IP header
    if protocol == 6:
        # TCP packet
        counters["ip"]["tcp"] += 1
        # Extract the TCP header
        tcp_header = struct.unpack("!HHLLBBHHH", raw_data[34:54])
        src_port = tcp_header[0]
        dst_port = tcp_header[1]

        # Check the ports in the TCP header
        if src_port == 80 or dst_port == 80:
            # HTTP packet
            counters["application"]["http"] += 1
        elif src_port == 22 or dst_port == 22:
            # SSH packet
            counters["application"]["ssh"] += 1
        elif src_port == 25 or dst_port == 25:
            # SMTP packet
            counters["application"]["smtp"] += 1
        elif src_port == 443 or dst_port == 443:
            counters["application"]["https"]+= 1
        else:
            # Other application packet
            counters["application"]["others"] += 1
    elif protocol == 17:
        # UDP packet
        udp_proto(raw_data)
    elif protocol == 1:
        counters["ip"]["icmp"]
    else:
        counters["ip"]["others"]+=1


def filtered_packeges(next_proto, raw_data):
    # Check the next protocol in the Ethernet header
        if next_proto == '0x800':#IPV4
            ip_layer(raw_data)

        elif next_proto == '0x806':#Who is this IP?
            # ARP packet
            counters["ethernet"]["arp"] += 1
        elif next_proto == '0x86dd':#IPV6
            if debug:
                print('IPV6 Package \n')
            counters["ip_version"]["ipv6"] += 1
        else:
            counters["ethernet"]["others"]+= 1

def capture_packages(raw_socket):
    while True:
        # Receive a packet from the socket
        raw_data, addr = raw_socket.recvfrom(65536)

        #So the user knows how many packages have been captured.
        if screen_count:
            print("\033[F", end="")  # Move the cursor to the beginning of the current line
            print("Total packages captured",counters["ethernet"]["ip"] + counters["ethernet"]["arp"] + counters["ethernet"]["others"]+counters["ip_version"]["ipv6"])
        # Extract the Ethernet header
        eth_header = struct.unpack("!6s6sH", raw_data[0:14])
        # For future applications can be used to know to which 
        # divice the computer is comunicating.
        dst_mac = binascii.hexlify(eth_header[0])
        src_mac = binascii.hexlify(eth_header[1])
        proto_type = eth_header[2]
        next_proto = hex(proto_type)

        filtered_packeges(next_proto,raw_data)

        


# Main function
def main():
    # Create a raw socket
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #raw_socket.bind(("wlan0",0)) #interface you want to 
    print("\n")
    # Loop for packets
    capture_packages(raw_socket)
    

#to run the program
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        exit_gracefully()
