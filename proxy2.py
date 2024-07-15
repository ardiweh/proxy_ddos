from scapy.all import sniff, IP, TCP, UDP, send

# Define the target IP and ports mapping for forwarding the packets
TARGET_IP = '192.168.1.100'
TARGET_PORT_MAPPING = { # gak dipake
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

def forward_packet(packet):
    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None
        
        if packet.haslayer(TCP):
            original_tcp = packet[TCP]
            new_packet = IP(src=original_ip.src, dst=TARGET_IP) / TCP(
                sport=original_tcp.sport, dport=original_tcp.dport, flags=original_tcp.flags,
                seq=original_tcp.seq, ack=original_tcp.ack, dataofs=original_tcp.dataofs, reserved=original_tcp.reserved,
                window=original_tcp.window, chksum=original_tcp.chksum, urgptr=original_tcp.urgptr, options=original_tcp.options
            ) / original_tcp.payload
                
        elif packet.haslayer(UDP):
            original_udp = packet[UDP]
            new_packet = IP(src=original_ip.src, dst=TARGET_IP) / UDP(
                sport=original_udp.sport, dport=original_udp.dport, len=original_udp.len, chksum=original_udp.chksum
            ) / original_udp.payload

        if new_packet:
            send(new_packet, verbose=False)
            print(f"Forwarded {packet.summary()} from {original_ip.src}:{original_tcp.sport if packet.haslayer(TCP) else original_udp.sport} to {TARGET_IP}:{original_tcp.dport if packet.haslayer(TCP) else original_udp.dport}")

# Start sniffing and forward packets
sniff(filter="tcp or udp", prn=forward_packet)
