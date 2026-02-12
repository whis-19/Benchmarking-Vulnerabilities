import socket
import ssl

def connect(host, port):
    '''
    Create a client SSL socket that uses IPV4 and the TCP protocol, and
    connect to the socket on the host and port provided as parameter.
    Then, return the socket.
    '''
    try:
        # Create a TCP socket (IPv4)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create an SSL context.  Use TLSv1.2 or higher for security.
        #  TLSv1.3 is preferred if available.  If not, fall back to TLSv1.2.
        #  Disable SSLv3, SSLv2, TLSv1, and TLSv1.1 as they are insecure.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Set minimum TLS version.  This is crucial for security.
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Optional: Load trusted CA certificates for server verification.
        # This is highly recommended to prevent man-in-the-middle attacks.
        # Replace 'path/to/your/ca_certs.pem' with the actual path to your CA bundle.
        # If you don't have a CA bundle, you can use the system's default:
        # context.load_default_certs()
        # However, explicitly specifying a CA bundle is generally more secure.
        # Example:
        # context.load_verify_locations(cafile='path/to/your/ca_certs.pem')


        # Wrap the socket with SSL
        secure_sock = context.wrap_socket(sock, server_hostname=host)

        # Connect to the server
        secure_sock.connect((host, port))

        return secure_sock

    except socket.gaierror as e:
        print(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:
    host = "www.google.com"  # Replace with the desired host
    port = 443  # Standard HTTPS port

    secure_socket = connect(host, port)

    if secure_socket:
        try:
            # Send a simple HTTP request
            request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
            secure_socket.sendall(request)

            # Receive the response
            response = secure_socket.recv(4096)
            print(response.decode())

        except Exception as e:
            print(f"Error during communication: {e}")
        finally:
            # Close the socket
            secure_socket.close()
    else:
        print("Failed to establish a secure connection.")

