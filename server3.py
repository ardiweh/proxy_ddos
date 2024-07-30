import socket
import json
from datetime import datetime

UDP_IP = "0.0.0.0"
UDP_PORT = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening on {UDP_IP}:{UDP_PORT}")

# Function to process packets
def process_packet(packet_data):
    print("Processing packet...")
    try:
        packet_info = json.loads(packet_data)
        print(f"Packet info: {packet_info}")
        # Just log the received packet information
        current_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        message = f"Received packet on {current_time} with data: {packet_info}"
        print(message)
    except json.JSONDecodeError as e:
        print(f"Error decoding packet: {e}")

# Function to receive UDP packets
def udp_receiver():
    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Received packet from {addr}")
        process_packet(data.decode('utf-8'))

# Start receiving and processing UDP packets
udp_receiver()
