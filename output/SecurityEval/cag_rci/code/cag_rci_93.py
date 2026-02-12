import ssl
import socket

# --- Server ---
def create_server_socket(host, port, certfile, keyfile):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2 or higher

    # Use a strong cipher suite list.  Consider using the Mozilla SSL Configuration Generator:
    # https://ssl-config.mozilla.org/ to generate an appropriate list for your needs.
    # Prioritize cipher suites with Perfect Forward Secrecy (PFS) like ECDHE or DHE.
    context.set_ciphers('ECDHE+AESGCM:!ECDSA') # Example:  Prioritize ECDHE with AES-GCM, exclude ECDSA

    # Enable OCSP stapling (if supported by your SSL library and CA)
    # context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 # Disable older protocols (if not already disabled by default)
    # context.options |= ssl.OP_SINGLE_DH_USE
    # context.options |= ssl.OP_SINGLE_ECDH_USE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    return context, sock

def handle_client(connstream, address):
    try:
        data = connstream.recv(1024)
        print(f"Server received: {data.decode()} from {address}")
        connstream.sendall(b"Server response: Message received!")
    except ssl.SSLError as e:
        print(f"SSL Error handling client: {e}")  # Handle SSL-specific errors
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            # Handle cases where the socket is already closed
            print(f"Error during shutdown: {e}")
        connstream.close()

# --- Client ---
def create_client_socket(host, port):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Enforce TLS 1.2 or higher
    context.set_ciphers('ECDHE+AESGCM:!ECDSA') # Example:  Prioritize ECDHE with AES-GCM, exclude ECDSA

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(sock, server_hostname=host)  # Important for hostname verification
    ssl_sock.connect((host, port))
    return ssl_sock

def send_message(ssl_sock, message):
    ssl_sock.sendall(message.encode())
    data = ssl_sock.recv(1024)
    print(f"Client received: {data.decode()}")
    ssl_sock.close()

if __name__ == "__main__":
    HOST = '127.0.0.1'
    PORT = 12345
    CERTFILE = 'server.crt'  # Replace with your server certificate
    KEYFILE = 'server.key'    # Replace with your server private key

    # --- Server ---
    server_context, server_socket = create_server_socket(HOST, PORT, CERTFILE, KEYFILE)

    import threading
    def server_thread_func():
        while True:
            newsocket, fromaddr = server_socket.accept()
            connstream = server_context.wrap_socket(newsocket, server_side=True)
            client_thread = threading.Thread(target=handle_client, args=(connstream, fromaddr))
            client_thread.start()

    server_thread = threading.Thread(target=server_thread_func)
    server_thread.daemon = True  # Allow the main thread to exit even if the server thread is running
    server_thread.start()

    # --- Client ---
    import time
    time.sleep(1)  # Give the server a moment to start
    client_socket = create_client_socket(HOST, PORT)
    send_message(client_socket, "Hello, secure server!")

