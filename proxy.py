import socket
import threading
import pandas as pd
from scapy.all import IP, TCP
from statistics import mean, stdev
from collections import defaultdict
import time

# Daftar port yang sering digunakan untuk DDoS
ddos_ports = {
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    22: 'SSH',
    21: 'FTP',
    25: 'SMTP',
    123: 'NTP',
    389: 'LDAP',
    1900: 'SSDP',
    1433: 'MSSQL',
    3389: 'RDP',
}

# Variabel global untuk menyimpan jumlah koneksi
connection_counts = defaultdict(int)
lock = threading.Lock()
data_list = []

# Fungsi untuk mendeteksi DDoS
def detect_ddos(port):
    global connection_counts
    threshold = 100  # Sesuaikan threshold sesuai kebutuhan Anda
    while True:
        time.sleep(10)  # Interval pemeriksaan
        with lock:
            count = connection_counts[port]
            connection_counts[port] = 0  # Reset count setelah pemeriksaan
            print("Port: " + str(port), " Connection Count: " + str(connection_counts))
        if count > threshold:
            print(f"Possible DDoS attack detected on port {port} ({ddos_ports[port]}): {count} connections in the last 10 seconds")

# Fungsi untuk ekstraksi fitur dari paket
def extract_features(packet):
    features = {}
    try:
        if IP in packet:
            features['protocol'] = packet[IP].proto
            features['flow_duration'] = packet.time

            # Forward and Backward Packet Lengths
            fwd_lengths = []
            bwd_lengths = []

            if TCP in packet:
                fwd_lengths.append(len(packet[TCP].payload))
                bwd_lengths.append(len(packet[TCP].payload))

                features['total_fwd_packets'] = len(fwd_lengths)
                features['total_backward_packets'] = len(bwd_lengths)
                features['fwd_packets_length_total'] = sum(fwd_lengths)
                features['bwd_packets_length_total'] = sum(bwd_lengths)
                features['fwd_packet_length_max'] = max(fwd_lengths) if fwd_lengths else 0
                features['fwd_packet_length_min'] = min(fwd_lengths) if fwd_lengths else 0
                features['fwd_packet_length_mean'] = mean(fwd_lengths) if fwd_lengths else 0
                features['fwd_packet_length_std'] = stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0
                features['bwd_packet_length_max'] = max(bwd_lengths) if bwd_lengths else 0
                features['bwd_packet_length_min'] = min(bwd_lengths) if bwd_lengths else 0
                features['bwd_packet_length_mean'] = mean(bwd_lengths) if bwd_lengths else 0
                features['bwd_packet_length_std'] = stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0

                # Inter Arrival Times
                flow_iat = [packet.time]
                fwd_iat = [packet.time]
                bwd_iat = [packet.time]

                features['flow_iat_mean'] = mean(flow_iat) if flow_iat else 0
                features['flow_iat_std'] = stdev(flow_iat) if len(flow_iat) > 1 else 0
                features['flow_iat_max'] = max(flow_iat) if flow_iat else 0
                features['flow_iat_min'] = min(flow_iat) if flow_iat else 0
                features['fwd_iat_total'] = sum(fwd_iat)
                features['fwd_iat_mean'] = mean(fwd_iat) if fwd_iat else 0
                features['fwd_iat_std'] = stdev(fwd_iat) if len(fwd_iat) > 1 else 0
                features['fwd_iat_max'] = max(fwd_iat) if fwd_iat else 0
                features['fwd_iat_min'] = min(fwd_iat) if fwd_iat else 0
                features['bwd_iat_total'] = sum(bwd_iat)
                features['bwd_iat_mean'] = mean(bwd_iat) if bwd_iat else 0
                features['bwd_iat_std'] = stdev(bwd_iat) if len(bwd_iat) > 1 else 0
                features['bwd_iat_max'] = max(bwd_iat) if bwd_iat else 0
                features['bwd_iat_min'] = min(bwd_iat) if bwd_iat else 0

                # Flags
                features['fwd_psh_flags'] = 1 if 'P' in str(packet[TCP].flags) else 0
                features['bwd_psh_flags'] = 1 if 'P' in str(packet[TCP].flags) else 0
                features['fwd_urg_flags'] = 1 if 'U' in str(packet[TCP].flags) else 0
                features['bwd_urg_flags'] = 1 if 'U' in str(packet[TCP].flags) else 0

                # Header Lengths
                features['fwd_header_length'] = len(packet[TCP]) - len(packet[TCP].payload)
                features['bwd_header_length'] = len(packet[TCP]) - len(packet[TCP].payload)

                # Packet Rates
                features['fwd_packets/s'] = len(fwd_lengths) / packet.time
                features['bwd_packets/s'] = len(bwd_lengths) / packet.time

                # Packet Length
                all_lengths = fwd_lengths + bwd_lengths
                features['packet_length_min'] = min(all_lengths) if all_lengths else 0
                features['packet_length_max'] = max(all_lengths) if all_lengths else 0
                features['pack_length_mean'] = mean(all_lengths) if all_lengths else 0
                features['packet_length_std'] = stdev(all_lengths) if len(all_lengths) > 1 else 0
                features['packet_length_variance'] = pd.Series(all_lengths).var() if len(all_lengths) > 1 else 0

                # Flags Count
                features['fin_flag_count'] = 1 if 'F' in str(packet[TCP].flags) else 0
                features['syn_flag_count'] = 1 if 'S' in str(packet[TCP].flags) else 0
                features['rst_flag_count'] = 1 if 'R' in str(packet[TCP].flags) else 0
                features['psh_flag_count'] = 1 if 'P' in str(packet[TCP].flags) else 0
                features['ack_flag_count'] = 1 if 'A' in str(packet[TCP].flags) else 0
                features['urg_flag_count'] = 1 if 'U' in str(packet[TCP].flags) else 0
                features['cwe_flag_count'] = 1 if 'C' in str(packet[TCP].flags) else 0
                features['ece_flag_count'] = 1 if 'E' in str(packet[TCP].flags) else 0

                # Down/Up Ratio
                down_up_ratio = len(bwd_lengths) / len(fwd_lengths) if len(fwd_lengths) > 0 else 0
                features['down/up_ratio'] = down_up_ratio

                # Average Packet Size
                avg_packet_size = (sum(fwd_lengths) + sum(bwd_lengths)) / (len(fwd_lengths) + len(bwd_lengths))
                features['avg_packet_size'] = avg_packet_size

                # Average Forward and Backward Segment Size
                features['avg_fwd_segment_size'] = sum(fwd_lengths) / len(fwd_lengths) if len(fwd_lengths) > 0 else 0
                features['avg_bwd_segment_size'] = sum(bwd_lengths) / len(bwd_lengths) if len(bwd_lengths) > 0 else 0

                # Bulk Rate Calculations
                features['fwd_avg_bytes/bulk'] = sum(fwd_lengths) / len(fwd_lengths) if len(fwd_lengths) > 0 else 0
                features['fwd_avg_packets/bulk'] = len(fwd_lengths)
                features['fwd_avg_bulk_rate'] = sum(fwd_lengths) / packet.time
                features['bwd_avg_bytes/bulk'] = sum(bwd_lengths) / len(bwd_lengths) if len(bwd_lengths) > 0 else 0
                features['bwd_avg_packets/bulk'] = len(bwd_lengths)
                features['bwd_avg_bulk_rate'] = sum(bwd_lengths) / packet.time

                # Subflow
                features['subflow_fwd_packets'] = len(fwd_lengths)
                features['subflow_fwd_bytes'] = sum(fwd_lengths)
                features['subflow_bwd_packets'] = len(bwd_lengths)
                features['subflow_bwd_bytes'] = sum(bwd_lengths)

                # Window Size
                features['init_fwd_win_bytes'] = packet[TCP].window
                features['init_bwd_win_bytes'] = packet[TCP].window

                # Active and Idle times
                active_times = [packet.time]
                idle_times = [packet.time]
                features['active_mean'] = mean(active_times) if active_times else 0
                features['active_std'] = stdev(active_times) if len(active_times) > 1 else 0
                features['active_max'] = max(active_times) if active_times else 0
                features['active_min'] = min(active_times) if active_times else 0
                features['idle_mean'] = mean(idle_times) if idle_times else 0
                features['idle_std'] = stdev(idle_times) if len(idle_times) > 1 else 0
                features['idle_max'] = max(idle_times) if idle_times else 0
                features['idle_min'] = min(idle_times) if idle_times else 0

    except AttributeError as e:
        print(f"Attribute error: {e}")

    return features

# Fungsi untuk memproses paket yang ditangkap
def process_packet(packet):
    with lock:
        connection_counts[packet[IP].dport] += 1  # Menggunakan dport untuk menghitung koneksi
    features = extract_features(packet)
    if features:
        data_list.append(features)
        print(f"Extracted features: {features}")

# Fungsi untuk menangani klien proxy
def handle_client(client_socket, server_address):
    with client_socket as source:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as destination:
            destination.connect(server_address)
            while True:
                data = source.recv(4096)
                if not data:
                    break

                try:
                    packet = IP(data)
                    # Check if it's an HTTP packet and ensure it's TCP
                    if packet.haslayer(TCP) and b'HTTP' in data:
                        features = extract_features(packet)
                        if features:
                            data_list.append(features)
                            print(f"Extracted features: {features}")
                except Exception as e:
                    print(f"Error processing packet: {e}")

                destination.sendall(data)
                response = destination.recv(4096)
                if not response:
                    break
                source.sendall(response)

# Fungsi untuk memulai listener dan proxy pada port tertentu
def start_listener_and_proxy(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"[*] Listening on port {port}")
        
        while True:
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            proxy_thread = threading.Thread(target=handle_client, args=(client_socket, ('remote.server.com', port)))
            proxy_thread.start()

# Membuat thread untuk mendengarkan pada port TCP dan UDP serta mendeteksi DDoS
def start_listening():
    threads = []

    for port in ddos_ports.keys():
        listener_proxy_thread = threading.Thread(target=start_listener_and_proxy, args=(port,))
        detect_thread = threading.Thread(target=detect_ddos, args=(port,))
        listener_proxy_thread.start()
        detect_thread.start()
        threads.append(listener_proxy_thread)
        threads.append(detect_thread)

    # Menunggu semua thread selesai
    for thread in threads:
        thread.join()

# Fungsi utama
if __name__ == "__main__":
    # Memulai pendengaran pada port, sniffing paket, dan proxy
    start_listening()
    
    # Simpan fitur jaringan yang diekstraksi ke file CSV
    df = pd.DataFrame(data_list)
    df.to_csv('network_traffic_features.csv', index=False)
    print("Network traffic features captured and saved to network_traffic_features.csv")
