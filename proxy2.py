from scapy.all import sniff, send, IP, TCP, UDP, wrpcap

# Define ports mapping for forwarding the packets
TARGET_PORT = {
    80,   # HTTP
    443,  # HTTPS
    53,   # DNS
    22,   # SSH
    21,   # FTP
    25,   # SMTP
    123,  # NTP
    389,  # LDAP
    1900, # SSDP
    1433, # MSSQL
    3389  # RDP
}

# Define the server IP address range or specific IPs
SERVER_IP_RANGE = '192.168.1.25'  # Should be a list or range for better flexibility

captured_packets = []
packet_count = 0
cap_increment = 0

def forward_packet(packet):
    global captured_packets, packet_count, cap_increment

    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None
        
        if packet.haslayer(TCP):
            original_tcp = packet[TCP]

            if original_tcp.dport not in TARGET_PORT:
                return

            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / TCP(
                sport=original_tcp.sport, dport=original_tcp.dport, flags=original_tcp.flags,
                seq=original_tcp.seq, ack=original_tcp.ack, dataofs=original_tcp.dataofs, reserved=original_tcp.reserved,
                window=original_tcp.window, chksum=original_tcp.chksum, urgptr=original_tcp.urgptr, options=original_tcp.options
            ) / original_tcp.payload
                
        elif packet.haslayer(UDP):
            original_udp = packet[UDP]

            if original_udp.dport not in TARGET_PORT:
                return
            
            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / UDP(
                sport=original_udp.sport, dport=original_udp.dport, len=original_udp.len, chksum=original_udp.chksum
            ) / original_udp.payload

        if original_ip.dst == SERVER_IP_RANGE:
            captured_packets.append(packet)
            packet_count += 1

        if packet_count >= 10:
            wrpcap(f"./log/client_traffic-{cap_increment}.pcap", captured_packets)
            cap_increment += 1
            packet_count = 0
            captured_packets.clear()

        if new_packet:
            send(new_packet, verbose=False)
            print(f"Forwarded {packet.summary()} from {original_ip.src}:{original_tcp.sport if packet.haslayer(TCP) else original_udp.sport} to {new_packet[IP].dst}:{new_packet[TCP].dport if packet.haslayer(TCP) else new_packet[UDP].dport}")

# Start sniffing and forward packets
sniff(filter="tcp or udp", prn=forward_packet)
