from scapy.all import sniff, send, IP, UDP
import os
import threading
import time
import csv

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

# Definisi alamat IP server dan proxy
SERVER_IP = '192.168.1.8'
PROXY_IP = '192.168.1.10'
CAPTURED_PACKET_DIR = "./log"

captured_data = []
packet_count = 0
cap_increment = 0
lock = threading.Lock()

# Fungsi untuk memeriksa apakah IP adalah multicast atau broadcast
def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

def forward_packet(packet):
    global captured_data, packet_count, cap_increment

    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None

        # Tambahkan pengecekan apakah IP tujuan adalah multicast atau broadcast
        if is_multicast_or_broadcast(original_ip.dst):
            return

        # Cegah loop dengan mengabaikan paket yang berasal dari PROXY_IP atau ditujukan ke PROXY_IP
        if original_ip.src == PROXY_IP or original_ip.dst == PROXY_IP:
            print("Ignoring packet from or to proxy itself to prevent loop.")
            return

        packet_info = {
            "Protocol": None,
            "Packet length": len(packet),
            "Flow Bytes": len(packet[IP]),  # Misalkan jumlah byte dari paket IP
            "Flow Packet": 1,               # Misalkan jumlah paket dalam aliran ini
            "Flow IAT": None,
            "IAT": packet.time,
            "PSH Flags": None,
            "URG Flags": None,
            "Header Length": None,
            "FIN Flag": None,
            "SYN Flag": None,
            "RST Flag": None,
            "PSH Flag": None,
            "ACK Flag": None,
            "URG Flag": None,
            "CWE Flag": None,
            "ECE Flag": None,
            "Packet Size": len(packet),
            "Segment Size": None,
            "Bytes/Bulk": None,
            "Packets/Bulk": None,
            "Bulk Rate": None,
            "Subflow Packets": 1,            # Misalkan jumlah subflow packets
            "Subflow Bytes": len(packet),    # Misalkan jumlah byte subflow
            "Init Win Bytes": None,
            "Active": packet.time,
            "Idle": None
        }

        if packet.haslayer(UDP):
            original_udp = packet[UDP]

            packet_info["Protocol"] = "UDP"

            new_packet = IP(src=original_ip.src, dst=SERVER_IP) / UDP(
                sport=original_udp.sport, dport=12345, len=original_udp.len, chksum=original_udp.chksum
            ) / original_udp.payload

        # Periksa apakah IP tujuan adalah SERVER_IP dan bukan multicast atau broadcast
        if new_packet:
            print(f"Forwarding packet from {original_ip.src} to {new_packet[IP].dst}")
            try:
                send(new_packet, verbose=False)
                print(f"Packet forwarded: {packet.summary()}")
            except Exception as e:
                print(f"Error forwarding packet: {e}")
        else:
            print("No new packet to forward.")

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
sniff(filter="udp", prn=forward_packet)
