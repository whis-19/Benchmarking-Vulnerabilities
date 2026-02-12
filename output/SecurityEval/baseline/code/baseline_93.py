import socket
import threading

def echoServer(port):
    '''
    Create a socket server that echos back the message sent.
    '''

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('', port)  # Listen on all available interfaces
    try:
        server_socket.bind(server_address)
        server_socket.listen(5)  # Listen for incoming connections (backlog of 5)
        print(f"Echo server listening on port {port}")

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")

            # Handle each client connection in a separate thread to allow concurrent connections
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()

    except OSError as e:
        print(f"Error: Could not bind to port {port}.  Another process might be using it.  Details: {e}")
    finally:
        server_socket.close()  # Ensure the socket is closed on exit


def handle_client(client_socket, client_address):
    """Handles the communication with a single client."""
    try:
        while True:
            data = client_socket.recv(1024)  # Receive data from the client (up to 1024 bytes)
            if not data:
                # Connection closed by client
                print(f"Connection closed by {client_address}")
                break

            # Echo the data back to the client
            client_socket.sendall(data)  # Use sendall to ensure all data is sent
            print(f"Echoed data back to {client_address}: {data.decode('utf-8', errors='ignore')}") # Decode for logging

    except ConnectionResetError:
        print(f"Connection reset by {client_address}")
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()  # Close the client socket when done


if __name__ == '__main__':
    PORT = 12345  # Choose a port number (above 1024)
    echoServer(PORT)

