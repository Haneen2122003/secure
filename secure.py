import socket
import threading
import rsa
from cryptography.fernet import Fernet

# Generate RSA keys
public_key, private_key = rsa.newkeys(512)

# Store shared key (will be set after exchange)
shared_key = None

def handle_client(client_socket):
    global shared_key
    
    # Receive and decrypt shared key
    encrypted_key = client_socket.recv(1024)
    shared_key = rsa.decrypt(encrypted_key, private_key)
    cipher = Fernet(shared_key)
    
    print("Secure communication established.")
    
    while True:
        encrypted_msg = client_socket.recv(1024)
        if not encrypted_msg:
            break
        decrypted_msg = cipher.decrypt(encrypted_msg).decode()
        print(f"Client: {decrypted_msg}")

        response = input("You: ")
        encrypted_response = cipher.encrypt(response.encode())
        client_socket.send(encrypted_response)
    
    client_socket.close()

# Server setup
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(1)
    print("Server listening on port 5555...")
    
    client_socket, addr = server.accept()
    print(f"Connection from {addr}")
    
    # Send public key
    client_socket.send(public_key.save_pkcs1())
    
    handle_client(client_socket)

# Client setup
def start_client():
    global shared_key
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 5555))
    
    # Receive server's public key
    server_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
    
    # Generate and encrypt shared key
    shared_key = Fernet.generate_key()
    encrypted_key = rsa.encrypt(shared_key, server_public_key)
    client.send(encrypted_key)
    
    cipher = Fernet(shared_key)
    
    while True:
        msg = input("You: ")
        encrypted_msg = cipher.encrypt(msg.encode())
        client.send(encrypted_msg)
        
        encrypted_response = client.recv(1024)
        decrypted_response = cipher.decrypt(encrypted_response).decode()
        print(f"Server: {decrypted_response}")
    
    client.close()


if __name__ == "__main__":
    choice = input("Start as (server/client): ").strip().lower()
    if choice == "server":
        start_server()
    elif choice == "client":
        start_client()
    else:
        print("Invalid choice.")

