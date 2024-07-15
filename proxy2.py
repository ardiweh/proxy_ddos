from scapy.all import sniff, send, IP, TCP, UDP, wrpcap

# Define ports mapping for forwarding the packets
TARGET_PORT_MAPPING = {
    80: 8080,   # HTTP
    443: 8443,  # HTTPS
    53: 8053,   # DNS
    22: 8022,   # SSH
    21: 8021,   # FTP
    25: 8025,   # SMTP
    123: 8123,  # NTP
    389: 8389,  # LDAP
    1900: 8190, # SSDP
    1433: 8433, # MSSQL
    3389: 8389  # RDP
}

# Define the client and server IP address ranges or specific IPs
# CLIENT_IP_RANGE = '192.168.1.0/24'
SERVER_IP_RANGE = '192.168.1.25'

captured_packets = []
packet_count = 0
cap_increment = 0

def forward_packet(packet):
    global captured_packets
    global packet_count
    global cap_increment

    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None
        
        if packet.haslayer(TCP):
            original_tcp = packet[TCP]
            
            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / TCP(
                sport=original_tcp.sport, dport=original_tcp.dport, flags=original_tcp.flags,
                seq=original_tcp.seq, ack=original_tcp.ack, dataofs=original_tcp.dataofs, reserved=original_tcp.reserved,
                window=original_tcp.window, chksum=original_tcp.chksum, urgptr=original_tcp.urgptr, options=original_tcp.options
            ) / original_tcp.payload
                
                
        elif packet.haslayer(UDP):
            original_udp = packet[UDP]
            
            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / UDP(
                sport=original_udp.sport, dport=original_udp.dport, len=original_udp.len, chksum=original_udp.chksum
            ) / original_udp.payload

        if original_ip.src in SERVER_IP_RANGE:
            # jangan log ketika ada trafic dari server
            pass
        else :
            captured_packets.append(packet)
            packet_count += 1

        if packet_count >= 10 :
            wrpcap("client_traffic-" + cap_increment + ".pcap", captured_packets)
            cap_increment += 1
            packet_count = 0
            captured_packets.clear()

        if new_packet:
            send(new_packet, verbose=False)
            print(f"Forwarded {packet.summary()} from {original_ip.src}:{original_tcp.sport if packet.haslayer(TCP) else original_udp.sport} to {new_packet[IP].dst}:{new_packet[TCP].dport if packet.haslayer(TCP) else new_packet[UDP].dport}")

# Start sniffing and forward packets
sniff(filter="tcp or udp", prn=forward_packet)
