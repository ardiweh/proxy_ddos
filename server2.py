import socket
import joblib
import pandas as pd
import numpy as np
from scapy.all import IP, UDP, TCP
import requests
from datetime import datetime

# Load the trained model, PCA, and scaler
model = joblib.load('best_random_forest_model.pkl')
pca = joblib.load('pca.pkl')
scaler = joblib.load('scaler.pkl')

# Telegram bot configuration
bot_token = '6863113423:AAHm97MiFDMfFPOg6mIcw_RLPmfk2zRF5xM'
bot_chatID = '6430179992'

UDP_IP = "0.0.0.0"
UDP_PORT = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening on {UDP_IP}:{UDP_PORT}")

# Define features to capture
feature_names = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "BWD URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min", "Packet Length Max",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init Fwd Win Bytes", "Init Bwd Win Bytes",
    "Fwd Act Data Packets", "Fwd Seg Size Min", "Active Mean", "Active Std",
    "Active Max", "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# Function to send message to Telegram
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

# Function to process packets
def process_packet(packet):
    print("Processing packet...")
    if packet.haslayer(IP):
        print("Packet has IP layer...")
        packet_info = {
            "Protocol": 1 if packet.haslayer(UDP) else 2 if packet.haslayer(TCP) else 0,
            "Packet length": len(packet),
            "Flow Duration": packet.time,  # Misalnya menggunakan timestamp dari Scapy
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
            "Flow Bytes/s": len(packet) / packet.time,
            "Flow Packets/s": 1 / packet.time,
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
            "Fwd Header Length": packet[IP].ihl * 4,
            "Bwd Header Length": 0,
            "Fwd Packets/s": 1 / packet.time,
            "Bwd Packets/s": 0,
            "Packet Length Min": len(packet),
            "Packet Length Max": len(packet),
            "Packet Length Mean": len(packet),
            "Packet Length Std": 0,
            "Packet Length Variance": 0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x02 else 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x08 else 0,
            "ACK Flag Count": 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x10 else 0,
            "URG Flag Count": 1 if packet.haslayer(TCP) and packet[TCP].flags & 0x20 else 0,
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
            "Init Fwd Win Bytes": packet[TCP].window if packet.haslayer(TCP) else 0,
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

        print(f"Packet info: {packet_info}")
        packet_df = pd.DataFrame([packet_info], columns=feature_names)

        try:
            packet_scaled = scaler.transform(packet_df)
            packet_pca = pca.transform(packet_scaled)
            print("Data transformed successfully.")
        except Exception as e:
            print(f"Error in data transformation: {e}")
            return

        try:
            prediction = model.predict(packet_pca)
            print(f"Prediction: {prediction}")
        except Exception as e:
            print(f"Error in prediction: {e}")
            return

        if prediction[0] == 1:
            current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
            reason = "Detected anomalous traffic pattern matching DDoS characteristics."
            message = f"Deteksi serangan DDoS terdeteksi pada {current_time}! Segera periksa sistem Anda.\nReason: {reason}"
            print(message)
            send_telegram_message(message)
        else:
            print("No DDoS detected.")
    else:
        print("Packet does not have IP layer")

# Fungsi untuk menerima paket UDP dan memprosesnya menggunakan Scapy
def udp_receiver():
    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Received packet from {addr}")
        packet = IP(data)
        process_packet(packet)

# Mulai menerima dan memproses paket UDP
udp_receiver()
