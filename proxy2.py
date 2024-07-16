from scapy.all import sniff, send, IP, TCP, UDP, wrpcap

# Definisi port yang diinginkan untuk forwarding
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

# Definisi alamat IP server
SERVER_IP = '192.168.1.129'

captured_packets = []
packet_count = 0
cap_increment = 0

# Fungsi untuk memeriksa apakah IP adalah multicast atau broadcast
def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

def forward_packet(packet):
    global captured_packets, packet_count, cap_increment

    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None
        
        # Tambahkan pengecekan apakah IP tujuan adalah multicast atau broadcast
        if is_multicast_or_broadcast(original_ip.dst):
            return

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

        # Periksa apakah IP tujuan adalah SERVER_IP dan bukan multicast atau broadcast
        if original_ip.dst == SERVER_IP and not is_multicast_or_broadcast(original_ip.dst):
            captured_packets.append(packet)
            packet_count += 1

        if packet_count >= 10:
            try:
                wrpcap(f"./log/client_traffic-{cap_increment}.pcap", captured_packets)
                cap_increment += 1
                packet_count = 0
                captured_packets.clear()
            except Exception as e:
                print(f"Error writing to pcap file: {e}")

        if new_packet:
            # Cek apakah new_packet tidak mengarah ke IP asli untuk menghindari looping
            if new_packet[IP].dst != original_ip.src:
                try:
                    send(new_packet, verbose=False)
                    print(f"Forwarded {packet.summary()} from {original_ip.src}:{original_tcp.sport if packet.haslayer(TCP) else original_udp.sport} to {new_packet[IP].dst}:{new_packet[TCP].dport if packet.haslayer(TCP) else new_packet[UDP].dport}")
                except Exception as e:
                    print(f"Error forwarding packet: {e}")
            else:
                print("Detected potential loop, packet not forwarded.")

# Mulai menangkap dan meneruskan paket
sniff(filter="tcp or udp", prn=forward_packet)
