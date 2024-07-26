from scapy.all import sniff, send, IP, TCP, UDP
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

# Definisi alamat IP server dan proxy
SERVER_IP = '192.168.1.9'  # Alamat IP server yang menjalankan kode server
SERVER_PORT = 12345        # Port yang digunakan server untuk menerima paket
PROXY_IP = '192.168.1.10'  # Alamat IP dari proxy itu sendiri

# Fungsi untuk memeriksa apakah IP adalah multicast atau broadcast
def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

# Fungsi untuk meneruskan paket ke server
def forward_packet_to_server(packet):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(bytes(packet), (SERVER_IP, SERVER_PORT))
        print(f"Packet sent to server: {packet.summary()}")
    except Exception as e:
        print(f"Error sending packet to server: {e}")

def forward_packet(packet):
    if packet.haslayer(IP):
        original_ip = packet[IP]
        
        # Tambahkan pengecekan apakah IP tujuan adalah multicast atau broadcast
        if is_multicast_or_broadcast(original_ip.dst):
            print(f"Skipping multicast/broadcast packet: {original_ip.dst}")
            return

        # Cek apakah paket berasal dari atau menuju proxy itu sendiri
        if original_ip.src == PROXY_IP or original_ip.dst == PROXY_IP:
            print(f"Skipping packet to/from proxy itself: {original_ip.src} -> {original_ip.dst}")
            return

        # Forward only valid TCP and UDP packets
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                forward_packet_to_server(packet)
                print(f"Forwarded {packet.summary()} from {original_ip.src} to {SERVER_IP}:{SERVER_PORT}")
            except Exception as e:
                print(f"Error forwarding packet to server: {e}")

# Mulai menangkap dan meneruskan paket
sniff(filter="tcp or udp", prn=forward_packet)
