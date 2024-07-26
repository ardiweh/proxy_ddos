import socket
import joblib
import pandas as pd
import numpy as np
from scapy.all import IP, UDP, TCP
import requests
from datetime import datetime
import json

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
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
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
    packet_info = json.loads(packet.decode('utf-8'))

    # Convert 'Protocol' field to numeric value
    protocol_map = {"UDP": 1, "TCP": 2}
    packet_info["Protocol"] = protocol_map.get(packet_info["Protocol"], 0)

    print(f"Packet info: {packet_info}")
    packet_df = pd.DataFrame([packet_info], columns=feature_names)

    try:
        start_time = time.time()
        packet_scaled = scaler.transform(packet_df)
        packet_pca = pca.transform(packet_scaled)
        prediction = model.predict(packet_pca)
        end_time = time.time()
        print(f"Data transformed and prediction made in {end_time - start_time:.4f} seconds.")
        print(f"Prediction: {prediction}")
    except Exception as e:
        print(f"Error in data transformation or prediction: {e}")
        return

    if prediction[0] == 1:
        current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        reason = "Detected anomalous traffic pattern matching DDoS characteristics."
        message = f"Deteksi serangan DDoS terdeteksi pada {current_time}! Segera periksa sistem Anda.\nReason: {reason}"
        print(message)
        send_telegram_message(message)
    else:
        print("No DDoS detected.")

# Fungsi untuk menerima paket UDP dan memprosesnya menggunakan Scapy
def udp_receiver():
    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Received packet from {addr}")
        process_packet(data)

# Mulai menerima dan memproses paket UDP
udp_receiver()
