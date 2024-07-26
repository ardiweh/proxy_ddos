from scapy.all import sniff, IP, TCP, UDP
import socket
import time
import json

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
SERVER_IP = '192.168.1.9'  # Alamat IP server yang menjalankan kode server
SERVER_PORT = 12345        # Port yang digunakan server untuk menerima paket
PROXY_IP = '192.168.1.10'  # Alamat IP dari proxy itu sendiri

# Fungsi untuk memeriksa apakah IP adalah multicast atau broadcast
def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

# Fungsi untuk meneruskan paket ke server
def forward_packet_to_server(metadata):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(metadata).encode('utf-8'), (SERVER_IP, SERVER_PORT))
        print(f"[INFO] Metadata sent to server: {metadata}")
    except Exception as e:
        print(f"[ERROR] Error sending metadata to server: {e}")

def extract_metadata(packet):
    metadata = {
        "Protocol": None,
        "Flow Duration": packet.time,
        "Total Fwd Packets": 1,
        "Total Backward Packets": 0,
        "Fwd Packets Length Total": len(packet),
        "Bwd Packets Length Total": 0,
        "Fwd Packet Length Max": len(packet),
        "Fwd Packet Length Min": len(packet),
        "Fwd Packet Length Mean": len(packet),
        "Fwd Packet Length Std": 0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Bwd Packet Length Std": 0,
        "Flow Bytes/s": 0,
        "Flow Packets/s": 0,
        "Flow IAT Mean": 0,
        "Flow IAT Std": 0,
        "Flow IAT Max": 0,
        "Flow IAT Min": 0,
        "Fwd IAT Total": 0,
        "Fwd IAT Mean": 0,
        "Fwd IAT Std": 0,
        "Fwd IAT Max": 0,
        "Fwd IAT Min": 0,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "BWD URG Flags": 0,
        "Fwd Header Length": 0,
        "Bwd Header Length": 0,
        "Fwd Packets/s": 0,
        "Bwd Packets/s": 0,
        "Packet Length Min": len(packet),
        "Packet Length Max": len(packet),
        "Packet Length Mean": len(packet),
        "Packet Length Std": 0,
        "Packet Length Variance": 0,
        "FIN Flag Count": 0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 0,
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": 0,
        "Avg Packet Size": len(packet),
        "Avg Fwd Segment Size": len(packet),
        "Avg Bwd Segment Size": 0,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": 1,
        "Subflow Fwd Bytes": len(packet),
        "Subflow Bwd Packets": 0,
        "Subflow Bwd Bytes": 0,
        "Init Fwd Win Bytes": 0,
        "Init Bwd Win Bytes": 0,
        "Fwd Act Data Packets": 0,
        "Fwd Seg Size Min": len(packet),
        "Active Mean": packet.time,
        "Active Std": 0,
        "Active Max": packet.time,
        "Active Min": packet.time,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0
    }

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        metadata["Protocol"] = "TCP"
        metadata["Fwd PSH Flags"] = tcp_layer.flags & 0x08
        metadata["Fwd URG Flags"] = tcp_layer.flags & 0x20
        metadata["Fwd Header Length"] = tcp_layer.dataofs * 4
        metadata["FIN Flag Count"] = tcp_layer.flags & 0x01
        metadata["SYN Flag Count"] = tcp_layer.flags & 0x02
        metadata["RST Flag Count"] = tcp_layer.flags & 0x04
        metadata["PSH Flag Count"] = tcp_layer.flags & 0x08
        metadata["ACK Flag Count"] = tcp_layer.flags & 0x10
        metadata["URG Flag Count"] = tcp_layer.flags & 0x20
        metadata["CWE Flag Count"] = tcp_layer.flags & 0x40
        metadata["ECE Flag Count"] = tcp_layer.flags & 0x80

    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        metadata["Protocol"] = "UDP"

    return metadata

def forward_packet(packet):
    if packet.haslayer(IP):
        original_ip = packet[IP]
        
        # Tambahkan pengecekan apakah IP tujuan adalah multicast atau broadcast
        if is_multicast_or_broadcast(original_ip.dst):
            print(f"[INFO] Skipping multicast/broadcast packet: {original_ip.dst}")
            return

        # Cek apakah paket berasal dari atau menuju proxy itu sendiri
        if original_ip.src == PROXY_IP or original_ip.dst == PROXY_IP:
            print(f"[INFO] Skipping packet to/from proxy itself: {original_ip.src} -> {original_ip.dst}")
            return

        # Log informasi paket yang diterima
        print(f"[INFO] Received packet: {original_ip.src} -> {original_ip.dst}")

        # Forward only valid TCP and UDP packets
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                metadata = extract_metadata(packet)
                forward_packet_to_server(metadata)
                print(f"[INFO] Forwarded {packet.summary()} from {original_ip.src} to {SERVER_IP}:{SERVER_PORT}")
            except Exception as e:
                print(f"[ERROR] Error forwarding packet to server: {e}")

# Mulai menangkap dan meneruskan paket
sniff(filter="tcp or udp", prn=forward_packet)
