import socket

UDP_IP = "0.0.0.0"  # Mendengarkan pada semua antarmuka
UDP_PORT = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening on {UDP_IP}:{UDP_PORT}")

while True:
    data, addr = sock.recvfrom(1024)  # Menerima paket hingga 1024 byte
    print(f"Received message: {data} from {addr}")
