from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import pandas as pd
import requests
import threading
from datetime import datetime

# Definisi alamat IP proxy
PROXY_IP = '192.168.1.176'  # Alamat IP dari proxy itu sendiri

# Load the model, scaler, and PCA using joblib
model = joblib.load('best_random_forest_model.pkl')
scaler = joblib.load('scaler.pkl')
pca = joblib.load('pca.pkl')

# Telegram bot configuration
bot_token = '6863113423:AAHm97MiFDMfFPOg6mIcw_RLPmfk2zRF5xM'
bot_chatID = '6430179992'

# Temporary log to store captured packet data
captured_packets = []

# Fungsi untuk memeriksa apakah IP adalah multicast atau broadcast
def is_multicast_or_broadcast(ip):
    return ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255'

# Fungsi untuk mengirim pesan ke Telegram
def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': bot_chatID,
        'text': message
    }
    try:
        response = requests.post(url, data=payload)
        print(f"Telegram response: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"Failed to send message to Telegram: {e}")

# Fungsi untuk mengekstraksi metadata dari paket
def extract_metadata(packet):
    print(packet)
    metadata = {
        "Protocol": 0,
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
        "Bwd URG Flags": 0,
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
        metadata["Protocol"] = 2
        metadata["Fwd PSH Flags"] = int(tcp_layer.flags & 0x08 != 0)
        metadata["Fwd URG Flags"] = int(tcp_layer.flags & 0x20 != 0)
        metadata["Fwd Header Length"] = tcp_layer.dataofs * 4
        metadata["FIN Flag Count"] = int(tcp_layer.flags & 0x01 != 0)
        metadata["SYN Flag Count"] = int(tcp_layer.flags & 0x02 != 0)
        metadata["RST Flag Count"] = int(tcp_layer.flags & 0x04 != 0)
        metadata["PSH Flag Count"] = int(tcp_layer.flags & 0x08 != 0)
        metadata["ACK Flag Count"] = int(tcp_layer.flags & 0x10 != 0)
        metadata["URG Flag Count"] = int(tcp_layer.flags & 0x20 != 0)
        metadata["CWE Flag Count"] = int(tcp_layer.flags & 0x40 != 0)
        metadata["ECE Flag Count"] = int(tcp_layer.flags & 0x80 != 0)

    elif packet.haslayer(UDP):
        metadata["Protocol"] = 1

    return metadata

# Fungsi untuk memprediksi berdasarkan metadata paket
def predict_packet(packet_metadata):
    # Ekstraksi fitur dan praproses menggunakan DataFrame untuk mempertahankan nama fitur
    feature_vector = pd.DataFrame([packet_metadata])
    scaled_features = scaler.transform(feature_vector)
    pca_features = pca.transform(scaled_features)
    
    # Prediksi menggunakan model
    prediction = model.predict(pca_features)
    return prediction

# Fungsi untuk menangani paket yang diterima
def forward_packet(packet):
    if packet.haslayer(IP):
        original_ip = packet[IP]
        
        # Pengecekan apakah IP tujuan adalah multicast atau broadcast
        if is_multicast_or_broadcast(original_ip.dst):
            print(f"[INFO] Skipping multicast/broadcast packet: {original_ip.dst}")
            return

        # Log informasi paket yang diterima
        print(f"[INFO] Received packet: {original_ip.src} -> {original_ip.dst}")

        # Hanya memproses paket TCP dan UDP yang valid
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                metadata = extract_metadata(packet)
                captured_packets.append(metadata)  # Simpan metadata ke log temporary
                
            except Exception as e:
                print(f"[ERROR] Error processing packet: {e}")

# Fungsi untuk memproses log temporary setiap 1 menit
def process_captured_packets():
    global captured_packets
    if captured_packets:
        try:
            for metadata in captured_packets:
                prediction = predict_packet(metadata)
                if prediction[0] == 1:
                    current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
                    message = f"Deteksi serangan DDoS terdeteksi pada {current_time}! Segera periksa sistem Anda."
                    print(message)
                    send_telegram_message(message)
        except Exception as e:
            print(f"[ERROR] Error in processing captured packets: {e}")
        finally:
            captured_packets = []  # Kosongkan log temporary

    # Jadwalkan ulang fungsi ini untuk berjalan lagi dalam 60 detik
    threading.Timer(60, process_captured_packets).start()

# Mulai fungsi proses log setiap 1 menit
process_captured_packets()

# Mulai menangkap dan memproses paket
sniff(filter="tcp or udp", prn=forward_packet)
