from scapy.all import sniff, send, IP, TCP, UDP
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

# Definisi alamat IP server
SERVER_IP = '192.168.1.8'
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

        if packet.haslayer(TCP):
            original_tcp = packet[TCP]

            if original_tcp.dport not in TARGET_PORT:
                return

            packet_info["Protocol"] = "TCP"
            packet_info["PSH Flags"] = original_tcp.flags & 0x08
            packet_info["URG Flags"] = original_tcp.flags & 0x20
            packet_info["Header Length"] = original_tcp.dataofs * 4
            packet_info["FIN Flag"] = original_tcp.flags & 0x01
            packet_info["SYN Flag"] = original_tcp.flags & 0x02
            packet_info["RST Flag"] = original_tcp.flags & 0x04
            packet_info["PSH Flag"] = original_tcp.flags & 0x08
            packet_info["ACK Flag"] = original_tcp.flags & 0x10
            packet_info["URG Flag"] = original_tcp.flags & 0x20
            packet_info["CWE Flag"] = original_tcp.flags & 0x40
            packet_info["ECE Flag"] = original_tcp.flags & 0x80

            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / TCP(
                sport=original_tcp.sport, dport=original_tcp.dport, flags=original_tcp.flags,
                seq=original_tcp.seq, ack=original_tcp.ack, dataofs=original_tcp.dataofs, reserved=original_tcp.reserved,
                window=original_tcp.window, chksum=original_tcp.chksum, urgptr=original_tcp.urgptr, options=original_tcp.options
            ) / original_tcp.payload
                
        elif packet.haslayer(UDP):
            original_udp = packet[UDP]

            if original_udp.dport not in TARGET_PORT:
                return
            
            packet_info["Protocol"] = "UDP"
            
            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / UDP(
                sport=original_udp.sport, dport=original_udp.dport, len=original_udp.len, chksum=original_udp.chksum
            ) / original_udp.payload

        # Periksa apakah IP tujuan adalah SERVER_IP dan bukan multicast atau broadcast
        if original_ip.dst == SERVER_IP and not is_multicast_or_broadcast(original_ip.dst):
            with lock:
                captured_data.append(packet_info)
                packet_count += 1

        if new_packet:
            # Cek apakah new_packet tidak mengarah ke IP asli untuk menghindari looping
            if new_packet[IP].dst != original_ip.src:
                try:
                    send(new_packet, verbose=False)
                    print(f"Forwarded {packet.summary()} from {original_ip.src} to {new_packet[IP].dst}")
                except Exception as e:
                    print(f"Error forwarding packet: {e}")
            else:
                print("Detected potential loop, packet not forwarded.")

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
