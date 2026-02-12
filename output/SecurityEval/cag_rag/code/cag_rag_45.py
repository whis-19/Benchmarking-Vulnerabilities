import ssl

def getSSLContext():
    '''
    Create an SSL context and return it.  This context is configured for enhanced security.
    '''
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)  # or ssl.Purpose.CLIENT_AUTH depending on use case

        # Set minimum TLS version.  TLS 1.2 is generally considered a good minimum.  TLS 1.3 is preferred if available.
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable compression to mitigate CRIME attack.  This is generally enabled by default.
        context.options |= ssl.OP_NO_COMPRESSION

        # Disable SSLv2, SSLv3, and TLSv1, TLSv1.1 as they are considered insecure.  These are often disabled by default, but it's good to be explicit.
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

        # Enable server certificate verification.  This is crucial for security.
        context.verify_mode = ssl.CERT_REQUIRED

        # Load the CA certificates that the server will use to verify client certificates (if client authentication is required).
        # Replace 'path/to/your/ca_bundle.pem' with the actual path to your CA bundle file.
        # If you don't need client authentication, you can skip this.
        # context.load_verify_locations('path/to/your/ca_bundle.pem')

        # Load the server certificate and private key.
        # Replace 'path/to/your/server.crt' and 'path/to/your/server.key' with the actual paths to your certificate and key files.
        # Ensure the key file has appropriate permissions (e.g., chmod 400).
        # context.load_cert_chain('path/to/your/server.crt', 'path/to/your/server.key')

        # Set ciphersuites.  Choose a strong set of ciphersuites.  The following is a good starting point.
        # This is crucial for negotiating a secure connection.  The exact ciphersuites available depend on the OpenSSL version.
        context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384')

        return context

    except Exception as e:
        print(f"Error creating SSL context: {e}")
        return None  # Or raise the exception, depending on the desired behavior

# Example usage (replace with your actual server/client code):
if __name__ == '__main__':
    ssl_context = getSSLContext()
    if ssl_context:
        print("SSL context created successfully.")
        # Example:  Create a socket using the SSL context (server-side example)
        # import socket
        # bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bindsocket.bind(('127.0.0.1', 4433))
        # bindsocket.listen(5)
        #
        # while True:
        #     newsocket, fromaddr = bindsocket.accept()
        #     connstream = ssl_context.wrap_socket(newsocket, server_side=True)
        #     try:
        #         data = connstream.recv(1024)
        #         # Process data
        #     finally:
        #         connstream.shutdown(socket.SHUT_RDWR)
        #         connstream.close()
    else:
        print("Failed to create SSL context.")

