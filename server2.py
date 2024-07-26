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
    packet_info = {
        "Protocol": packet["Protocol"],
        "Flow Duration": packet["Flow Duration"],
        "Total Fwd Packets": packet["Total Fwd Packets"],
        "Total Backward Packets": packet["Total Backward Packets"],
        "Fwd Packets Length Total": packet["Fwd Packets Length Total"],
        "Bwd Packets Length Total": packet["Bwd Packets Length Total"],
        "Fwd Packet Length Max": packet["Fwd Packet Length Max"],
        "Fwd Packet Length Min": packet["Fwd Packet Length Min"],
        "Fwd Packet Length Mean": packet["Fwd Packet Length Mean"],
        "Fwd Packet Length Std": packet["Fwd Packet Length Std"],
        "Bwd Packet Length Max": packet["Bwd Packet Length Max"],
        "Bwd Packet Length Min": packet["Bwd Packet Length Min"],
        "Bwd Packet Length Mean": packet["Bwd Packet Length Mean"],
        "Bwd Packet Length Std": packet["Bwd Packet Length Std"],
        "Flow Bytes/s": packet["Flow Bytes/s"],
        "Flow Packets/s": packet["Flow Packets/s"],
        "Flow IAT Mean": packet["Flow IAT Mean"],
        "Flow IAT Std": packet["Flow IAT Std"],
        "Flow IAT Max": packet["Flow IAT Max"],
        "Flow IAT Min": packet["Flow IAT Min"],
        "Fwd IAT Total": packet["Fwd IAT Total"],
        "Fwd IAT Mean": packet["Fwd IAT Mean"],
        "Fwd IAT Std": packet["Fwd IAT Std"],
        "Fwd IAT Max": packet["Fwd IAT Max"],
        "Fwd IAT Min": packet["Fwd IAT Min"],
        "Bwd IAT Total": packet["Bwd IAT Total"],
        "Bwd IAT Mean": packet["Bwd IAT Mean"],
        "Bwd IAT Std": packet["Bwd IAT Std"],
        "Bwd IAT Max": packet["Bwd IAT Max"],
        "Bwd IAT Min": packet["Bwd IAT Min"],
        "Fwd PSH Flags": packet["Fwd PSH Flags"],
        "Bwd PSH Flags": packet["Bwd PSH Flags"],
        "Fwd URG Flags": packet["Fwd URG Flags"],
        "BWD URG Flags": packet["BWD URG Flags"],
        "Fwd Header Length": packet["Fwd Header Length"],
        "Bwd Header Length": packet["Bwd Header Length"],
        "Fwd Packets/s": packet["Fwd Packets/s"],
        "Bwd Packets/s": packet["Bwd Packets/s"],
        "Packet Length Min": packet["Packet Length Min"],
        "Packet Length Max": packet["Packet Length Max"],
        "Packet Length Mean": packet["Packet Length Mean"],
        "Packet Length Std": packet["Packet Length Std"],
        "Packet Length Variance": packet["Packet Length Variance"],
        "FIN Flag Count": packet["FIN Flag Count"],
        "SYN Flag Count": packet["SYN Flag Count"],
        "RST Flag Count": packet["RST Flag Count"],
        "PSH Flag Count": packet["PSH Flag Count"],
        "ACK Flag Count": packet["ACK Flag Count"],
        "URG Flag Count": packet["URG Flag Count"],
        "CWE Flag Count": packet["CWE Flag Count"],
        "ECE Flag Count": packet["ECE Flag Count"],
        "Down/Up Ratio": packet["Down/Up Ratio"],
        "Avg Packet Size": packet["Avg Packet Size"],
        "Avg Fwd Segment Size": packet["Avg Fwd Segment Size"],
        "Avg Bwd Segment Size": packet["Avg Bwd Segment Size"],
        "Fwd Avg Bytes/Bulk": packet["Fwd Avg Bytes/Bulk"],
        "Fwd Avg Packets/Bulk": packet["Fwd Avg Packets/Bulk"],
        "Fwd Avg Bulk Rate": packet["Fwd Avg Bulk Rate"],
        "Bwd Avg Bytes/Bulk": packet["Bwd Avg Bytes/Bulk"],
        "Bwd Avg Packets/Bulk": packet["Bwd Avg Packets/Bulk"],
        "Bwd Avg Bulk Rate": packet["Bwd Avg Bulk Rate"],
        "Subflow Fwd Packets": packet["Subflow Fwd Packets"],
        "Subflow Fwd Bytes": packet["Subflow Fwd Bytes"],
        "Subflow Bwd Packets": packet["Subflow Bwd Packets"],
        "Subflow Bwd Bytes": packet["Subflow Bwd Bytes"],
        "Init Fwd Win Bytes": packet["Init Fwd Win Bytes"],
        "Init Bwd Win Bytes": packet["Init Bwd Win Bytes"],
        "Fwd Act Data Packets": packet["Fwd Act Data Packets"],
        "Fwd Seg Size Min": packet["Fwd Seg Size Min"],
        "Active Mean": packet["Active Mean"],
        "Active Std": packet["Active Std"],
        "Active Max": packet["Active Max"],
        "Active Min": packet["Active Min"],
        "Idle Mean": packet["Idle Mean"],
        "Idle Std": packet["Idle Std"],
        "Idle Max": packet["Idle Max"],
        "Idle Min": packet["Idle Min"]
    }

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

# Fungsi untuk menerima paket UDP dan memprosesnya
def udp_receiver():
    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Received packet from {addr}")
        try:
            packet = eval(data.decode('utf-8'))
            process_packet(packet)
        except Exception as e:
            print(f"Error processing packet: {e}")

# Mulai menerima dan memproses paket UDP
udp_receiver()
