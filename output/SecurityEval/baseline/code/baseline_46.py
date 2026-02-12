from OpenSSL import SSL
import ssl  # Standard library ssl module for more secure defaults

def getContext(cert_file=None, key_file=None, ca_file=None, ssl_version=ssl.PROTOCOL_TLS_CLIENT):
    '''
    Create an OpenSSL context and return it.

    Args:
        cert_file (str, optional): Path to the certificate file (PEM format). Defaults to None.
        key_file (str, optional): Path to the private key file (PEM format). Defaults to None.
        ca_file (str, optional): Path to the CA certificate file (PEM format) for verifying the server. Defaults to None.
        ssl_version (int, optional):  The SSL/TLS protocol version to use.  Defaults to ssl.PROTOCOL_TLS_CLIENT (recommended).

    Returns:
        SSL.Context: The OpenSSL context.
    '''

    try:
        # Use the standard library's ssl module to create a more secure context
        # and then adapt it for use with pyOpenSSL.  This is the recommended approach.
        context = SSL.Context(ssl_version)

        # Load certificate and private key if provided
        if cert_file and key_file:
            context.use_certificate_file(cert_file)
            context.use_privatekey_file(key_file)

            # Optional: Verify the private key matches the certificate
            try:
                context.check_privatekey()
            except SSL.Error as e:
                raise ValueError(f"Private key does not match certificate: {e}")

        # Load CA certificates for server verification if provided
        if ca_file:
            context.load_verify_locations(cafile=ca_file)
            context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda conn, cert, errnum, errdepth, ok: ok)  # Enable server certificate verification

        # Set options for enhanced security
        context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_COMPRESSION)  # Disable vulnerable protocols and compression
        context.set_cipher_list('DEFAULT') # Use a secure cipher suite

        return context

    except SSL.Error as e:
        raise ValueError(f"Error creating SSL context: {e}")
    except OSError as e:
        raise ValueError(f"Error loading certificate or key file: {e}")


if __name__ == '__main__':
    # Example usage (replace with your actual file paths)
    try:
        context = getContext(cert_file="server.crt", key_file="server.key", ca_file="ca.crt")
        print("SSL Context created successfully.")

        # Example of creating a socket (this is just a placeholder, you'd need to
        # integrate this into your actual server/client code)
        from socket import socket, AF_INET, SOCK_STREAM
        sock = socket(AF_INET, SOCK_STREAM)
        ssl_sock = SSL.Connection(context, sock)

        # You would then use ssl_sock for secure communication.
        # For example, in a server:
        # ssl_sock.bind(('localhost', 443))
        # ssl_sock.listen(5)
        # conn, addr = ssl_sock.accept()
        # data = conn.recv(1024)
        # conn.sendall(b"Hello, client!")
        # conn.close()

    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

