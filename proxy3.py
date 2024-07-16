import joblib
from scapy.all import sniff, send, IP, TCP, UDP
import os
import pandas as pd
from datetime import datetime
import requests

# Definisi file model, scaler, dan PCA
MODEL_FILE = '/home/ardiweh/proxy-ddos/best_random_forest_model.pkl'
SCALER_FILE = '/home/ardiweh/proxy-ddos/scaler.pkl'
PCA_FILE = '/home/ardiweh/proxy-ddos/pca.pkl'

# Memuat model, scaler, dan PCA
model = joblib.load(best_random_forest_model.pkl)
scaler = joblib.load(scaler.pkl)
pca = joblib.load(pca.pkl)

TARGET_PORT = {80, 443, 53, 22, 21, 25, 123, 389, 1900, 1433, 3389}
SERVER_IP = '192.168.167.239'
CAPTURED_PACKET_DIR = "./log"
FEATURES_FILE = "./features.csv"
TELEGRAM_API_URL = "https://api.telegram.org/bot6863113423:AAHm97MiFDMfFPOg6mIcw_RLPmfk2zRF5xM/sendMessage"
CHAT_ID = '6430179992'

captured_packets = []
packet_count = 0
cap_increment = 0

if not os.path.exists(FEATURES_FILE):
    df = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"])
    df.to_csv(FEATURES_FILE, index=False)

def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

def save_features(packet):
    if packet.haslayer(IP):
        original_ip = packet[IP]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        protocol = "TCP" if packet.haslayer(TCP) else "UDP"
        src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

        new_row = {
            "timestamp": timestamp,
            "src_ip": original_ip.src,
            "dst_ip": original_ip.dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol
        }

        df = pd.read_csv(FEATURES_FILE)
        df = df.append(new_row, ignore_index=True)
        df.to_csv(FEATURES_FILE, index=False)

def forward_packet(packet):
    global captured_packets, packet_count, cap_increment

    if packet.haslayer(IP):
        original_ip = packet[IP]
        new_packet = None

        if is_multicast_or_broadcast(original_ip.dst):
            return
        
        if packet.haslayer(TCP):
            original_tcp = packet[TCP]
            if original_tcp.dport not in TARGET_PORT:
                return
            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / TCP(
                sport=original_tcp.sport, dport=original_tcp.dport, flags=original_tcp.flags,
                seq=original_tcp.seq, ack=original_tcp.ack, dataofs=original_tcp.dataofs,
                reserved=original_tcp.reserved, window=original_tcp.window,
                chksum=original_tcp.chksum, urgptr=original_tcp.urgptr,
                options=original_tcp.options
            ) / original_tcp.payload
                
        elif packet.haslayer(UDP):
            original_udp = packet[UDP]
            if original_udp.dport not in TARGET_PORT:
                return
            new_packet = IP(src=original_ip.src, dst=original_ip.dst) / UDP(
                sport=original_udp.sport, dport=original_udp.dport, len=original_udp.len,
                chksum=original_udp.chksum
            ) / original_udp.payload

        if original_ip.dst == SERVER_IP and not is_multicast_or_broadcast(original_ip.dst):
            captured_packets.append(packet)
            packet_count += 1
            save_features(packet)

        if packet_count >= 10:
            try:
                if not os.path.exists(CAPTURED_PACKET_DIR):
                    os.makedirs(CAPTURED_PACKET_DIR)
                wrpcap(os.path.join(CAPTURED_PACKET_DIR, f"client_traffic-{cap_increment}.pcap"), captured_packets)
                cap_increment += 1
                packet_count = 0
                captured_packets.clear()
            except Exception as e:
                print(f"Error writing to pcap file: {e}")

        if new_packet and new_packet[IP].dst != original_ip.src:
            try:
                send(new_packet, verbose=False)
                print(f"Forwarded {packet.summary()} from {original_ip.src}:{original_tcp.sport if packet.haslayer(TCP) else original_udp.sport} to {new_packet[IP].dst}:{new_packet[TCP].dport if packet.haslayer(TCP) else new_packet[UDP].dport}")
            except Exception as e:
                print(f"Error forwarding packet: {e}")

def notify_telegram(message):
    try:
        params = {'chat_id': CHAT_ID, 'text': message}
        requests.get(TELEGRAM_API_URL, params=params)
    except Exception as e:
        print(f"Error sending message to Telegram: {e}")

def detect_ddos():
    df = pd.read_csv(FEATURES_FILE)
    X = df[["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]]
    
    # Apply scaler and PCA
    X_scaled = scaler.transform(X)
    X_pca = pca.transform(X_scaled)
    
    y_pred = model.predict(X_pca)

    if sum(y_pred) > 0:  # Jika ada prediksi DDoS
        notify_telegram("DDoS detected!")

# Mulai menangkap dan meneruskan paket
sniff(filter="tcp or udp", prn=forward_packet)
