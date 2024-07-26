from scapy.all import sniff, send, IP, TCP, UDP
import os
import threading
import time
import csv
import socket

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
SERVER_IP = '192.168.1.9'  # Alamat IP server yang menjalankan kode server
SERVER_PORT = 12345         # Port yang digunakan server untuk menerima paket
PROXY_IP = '192.168.1.10'   # Alamat IP dari proxy itu sendiri
CAPTURED_PACKET_DIR = "./log"

captured_data = []
packet_count = 0
cap_increment = 0
lock = threading.Lock()

# Fungsi untuk memeriksa apakah IP adalah multicast atau broadcast
def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

# Fungsi untuk meneruskan paket ke server
def forward_packet_to_server(packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(packet), (SERVER_IP, SERVER_PORT))

def forward_packet(packet):
    global captured_data, packet_count, cap_increment

    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None
        
        # Tambahkan pengecekan apakah IP tujuan adalah multicast atau broadcast
        if is_multicast_or_broadcast(original_ip.dst):
            print(f"Skipping multicast/broadcast packet: {original_ip.dst}")
            return

        # Cek apakah paket sudah sampai ke tujuan akhir (SERVER_IP) atau berasal dari proxy itu sendiri
        if original_ip.src == PROXY_IP or original_ip.dst == PROXY_IP:
            print(f"Skipping packet to/from proxy itself: {original_ip.src} -> {original_ip.dst}")
            return

        if packet.haslayer(TCP):
            original_tcp = packet[TCP]

            if original_tcp.dport not in TARGET_PORT:
                print(f"Skipping packet with dport not in TARGET_PORT: {original_tcp.dport}")
                return

            new_packet = IP(src=original_ip.src, dst=SERVER_IP) / TCP(
                sport=original_tcp.sport, dport=original_tcp.dport, flags=original_tcp.flags,
                seq=original_tcp.seq, ack=original_tcp.ack, dataofs=original_tcp.dataofs, reserved=original_tcp.reserved,
                window=original_tcp.window, chksum=original_tcp.chksum, urgptr=original_tcp.urgptr, options=original_tcp.options
            ) / original_tcp.payload
                
        elif packet.haslayer(UDP):
            original_udp = packet[UDP]

            if original_udp.dport not in TARGET_PORT:
                print(f"Skipping packet with dport not in TARGET_PORT: {original_udp.dport}")
                return
            
            new_packet = IP(src=original_ip.src, dst=SERVER_IP) / UDP(
                sport=original_udp.sport, dport=original_udp.dport, len=original_udp.len, chksum=original_udp.chksum
            ) / original_udp.payload

        if new_packet:
            try:
                forward_packet_to_server(new_packet)
                print(f"Forwarded {packet.summary()} from {original_ip.src}:{original_tcp.sport if packet.haslayer(TCP) else original_udp.sport} to {SERVER_IP}:{SERVER_PORT}")
            except Exception as e:
                print(f"Error forwarding packet to server: {e}")

def write_logs():
    global captured_data, packet_count, cap_increment
    while True:
        time.sleep(1)
        with lock:
            if packet_count > 0:
                try:
                    # Pastikan direktori ada dan memiliki izin menulis
                    if not os.path.exists(CAPTURED_PACKET_DIR):
                        os.makedirs(CAPTURED_PACKET_DIR)
                    file_path = os.path.join(CAPTURED_PACKET_DIR, f"client_traffic-{cap_increment}.csv")
                    with open(file_path, 'w', newline='') as csvfile:
                        fieldnames = list(captured_data[0].keys())
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        for data in captured_data:
                            writer.writerow(data)
                    cap_increment += 1
                    packet_count = 0
                    captured_data.clear()
                except Exception as e:
                    print(f"Error writing to CSV file: {e}")

# Memulai thread untuk menulis log
log_thread = threading.Thread(target=write_logs)
log_thread.daemon = True
log_thread.start()

# Mulai menangkap dan meneruskan paket
sniff(filter="tcp or udp", prn=forward_packet)
