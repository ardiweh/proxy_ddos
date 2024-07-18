import socket

PROXY_IP = "192.168.1.10"  # Alamat IP dari proxy
PROXY_PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
message = "Test UDP packet"
sock.sendto(message.encode(), (PROXY_IP, PROXY_PORT))
print(f"Sent message: {message} to {PROXY_IP}:{PROXY_PORT}")
