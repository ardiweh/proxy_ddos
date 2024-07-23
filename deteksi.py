import socket
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, UDP, TCP
import requests

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
        requests.post(url, data=payload)
    except Exception as e:
        print(f"Failed to send message to Telegram: {e}")

# Function to process packets
def process_packet(packet):
    if packet.haslayer(IP):
        packet_info = {
            "Protocol": 1 if packet.haslayer(UDP) else 2 if packet.haslayer(TCP) else 0,
            "Packet length": len(packet),
            "Flow Duration": 0,  # Placeholder
            "Total Fwd Packets": 0,  # Placeholder
            "Total Backward Packets": 0,  # Placeholder
            "Fwd Packets Length Total": 0,  # Placeholder
            "Bwd Packets Length Total": 0,  # Placeholder
            "Fwd Packet Length Max": 0,  # Placeholder
            "Fwd Packet Length Min": 0,  # Placeholder
            "Fwd Packet Length Mean": 0,  # Placeholder
            "Fwd Packet Length Std": 0,  # Placeholder
            "Bwd Packet Length Max": 0,  # Placeholder
            "Bwd Packet Length Min": 0,  # Placeholder
            "Bwd Packet Length Mean": 0,  # Placeholder
            "Bwd Packet Length Std": 0,  # Placeholder
            "Flow Bytes/s": 0,  # Placeholder
            "Flow Packets/s": 0,  # Placeholder
            "Flow IAT Mean": 0,  # Placeholder
            "Flow IAT Std": 0,  # Placeholder
            "Flow IAT Max": 0,  # Placeholder
            "Flow IAT Min": 0,  # Placeholder
            "Fwd IAT Total": 0,  # Placeholder
            "Fwd IAT Mean": 0,  # Placeholder
            "Fwd IAT Std": 0,  # Placeholder
            "Fwd IAT Max": 0,  # Placeholder
            "Fwd IAT Min": 0,  # Placeholder
            "Bwd IAT Total": 0,  # Placeholder
            "Bwd IAT Mean": 0,  # Placeholder
            "Bwd IAT Std": 0,  # Placeholder
            "Bwd IAT Max": 0,  # Placeholder
            "Bwd IAT Min": 0,  # Placeholder
            "Fwd PSH Flags": 0,  # Placeholder
            "Bwd PSH Flags": 0,  # Placeholder
            "Fwd URG Flags": 0,  # Placeholder
            "BWD URG Flags": 0,  # Placeholder
            "Fwd Header Length": 0,  # Placeholder
            "Bwd Header Length": 0,  # Placeholder
            "Fwd Packets/s": 0,  # Placeholder
            "Bwd Packets/s": 0,  # Placeholder
            "Packet Length Min": 0,  # Placeholder
            "Packet Length Max": 0,  # Placeholder
            "Packet Length Mean": 0,  # Placeholder
            "Packet Length Std": 0,  # Placeholder
            "Packet Length Variance": 0,  # Placeholder
            "FIN Flag Count": 0,  # Placeholder
            "SYN Flag Count": 0,  # Placeholder
            "RST Flag Count": 0,  # Placeholder
            "PSH Flag Count": 0,  # Placeholder
            "ACK Flag Count": 0,  # Placeholder
            "URG Flag Count": 0,  # Placeholder
            "CWE Flag Count": 0,  # Placeholder
            "ECE Flag Count": 0,  # Placeholder
            "Down/Up Ratio": 0,  # Placeholder
            "Avg Packet Size": 0,  # Placeholder
            "Avg Fwd Segment Size": 0,  # Placeholder
            "Avg Bwd Segment Size": 0,  # Placeholder
            "Fwd Avg Bytes/Bulk": 0,  # Placeholder
            "Fwd Avg Packets/Bulk": 0,  # Placeholder
            "Fwd Avg Bulk Rate": 0,  # Placeholder
            "Bwd Avg Bytes/Bulk": 0,  # Placeholder
            "Bwd Avg Packets/Bulk": 0,  # Placeholder
            "Bwd Avg Bulk Rate": 0,  # Placeholder
            "Subflow Fwd Packets": 0,  # Placeholder
            "Subflow Fwd Bytes": 0,  # Placeholder
            "Subflow Bwd Packets": 0,  # Placeholder
            "Subflow Bwd Bytes": 0,  # Placeholder
            "Init Fwd Win Bytes": 0,  # Placeholder
            "Init Bwd Win Bytes": 0,  # Placeholder
            "Fwd Act Data Packets": 0,  # Placeholder
            "Fwd Seg Size Min": 0,  # Placeholder
            "Active Mean": 0,  # Placeholder
            "Active Std": 0,  # Placeholder
            "Active Max": 0,  # Placeholder
            "Active Min": 0,  # Placeholder
            "Idle Mean": 0,  # Placeholder
            "Idle Std": 0,  # Placeholder
            "Idle Max": 0,  # Placeholder
            "Idle Min": 0   # Placeholder
        }

        # Convert packet_info to dataframe
        packet_df = pd.DataFrame([packet_info], columns=feature_names)

        # Scale and transform the data
        packet_scaled = scaler.transform(packet_df)
        packet_pca = pca.transform(packet_scaled)

        # Predict with the model
        prediction = model.predict(packet_pca)

        if prediction[0] == 1:
            print(f"Detected DDoS attack from {packet[IP].src}")
            send_telegram_message(f"Detected DDoS attack from {packet[IP].src}")

while True:
    data, addr = sock.recvfrom(1024)
    packet = sniff(count=1)
    process_packet(packet[0])
