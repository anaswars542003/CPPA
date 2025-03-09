import socket

def start_server():
    host = '127.0.0.1'  # Localhost
    port = 12345        # Port to listen on

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind((host, port))
    print(f"Server started on {host}:{port}")

    # Listen for incoming connections
    server_socket.listen(1)

    while True:
        print("Waiting for a connection...")
        conn, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        # Receive 64 bytes of raw data
        data = conn.recv(64)
        if not data:
            break

        print(f"Received data (64 bytes): {data}")

        # Close the connection
        conn.close()
        print("Connection closed.\n")

if __name__ == "__main__":
    start_server()
