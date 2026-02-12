import ssl
import os
import logging
import getpass

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO)

def getSSLContext(certfile=None, keyfile=None, cafile=None, password=None, server_side=False):
    '''
    Create an SSL context and return it.

    Args:
        certfile (str, optional): Path to the certificate file. Defaults to None.
        keyfile (str, optional): Path to the private key file. Defaults to None.
        cafile (str, optional): Path to the CA certificate file for verifying the server. Defaults to None.
        password (str, optional): Password for the private key file, if encrypted. Defaults to None.  If None, the user will be prompted.
        server_side (bool, optional): True if creating a server-side context, False for client-side. Defaults to False.

    Returns:
        ssl.SSLContext: The created SSL context.  Returns None if context creation fails.

    Raises:
        FileNotFoundError: If certfile, keyfile, or cafile are specified but do not exist.
        ssl.SSLError: If there are issues loading the certificates or key.
        ValueError: If certfile is specified without keyfile, or vice versa.
    '''

    try:
        if server_side:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Check for mutual TLS (client authentication)
        if certfile and keyfile:
            if not os.path.exists(certfile):
                raise FileNotFoundError(f"Certificate file not found: {certfile}")
            if not os.path.exists(keyfile):
                raise FileNotFoundError(f"Key file not found: {keyfile}")

            # Prompt for password if not provided
            if password is None:
                password = getpass.getpass("Enter password for private key: ")

            context.load_cert_chain(certfile, keyfile, password=password)  # Load certificate and private key
            context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate verification
            # Hostname verification is generally not needed for client certificates, but consider enabling if appropriate for your use case.
            # If enabled, ensure the client certificate contains the expected hostname.
            # context.check_hostname = True

        elif certfile or keyfile:
            raise ValueError("Both certfile and keyfile must be specified for mutual TLS.")

        # Load CA certificates for server verification (if applicable)
        if cafile:
            if not os.path.exists(cafile):
                raise FileNotFoundError(f"CA file not found: {cafile}")
            context.load_verify_locations(cafile=cafile)
            context.verify_mode = ssl.CERT_REQUIRED  # Require server certificate verification
            context.check_hostname = True # Enable hostname verification for server authentication.

        # Set minimum TLS version (important for security)
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_3  # or TLSv1_2 if not supported
        except AttributeError:
            logging.warning("TLSv1_3 not supported, defaulting to TLSv1_2")
            context.minimum_version = ssl.TLSVersion.TLSv1_2


        # Disable compression (CRIME attack mitigation)
        context.options |= ssl.OP_NO_COMPRESSION

        # Disable SSLv2, SSLv3, and TLSv1, TLSv1.1 (POODLE, BEAST, etc. mitigation)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

        # Prefer server ciphers (mitigates some downgrade attacks)
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

        # Set ciphersuites (restrict to strong ciphers) -  Adjust based on your needs and OpenSSL version
        context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:TLS_CHACHA20_POLY1305_SHA256')


        return context

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return None
    except ssl.SSLError as e:
        logging.exception(f"SSL Error: {e}")
        return None
    except ValueError as e:
        logging.error(f"Value Error: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Use logging.exception to include traceback
        return None


if __name__ == '__main__':
    # Example usage (replace with your actual file paths)
    try:
        # Create a self-signed certificate and key for testing:
        # openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
        # openssl req -newkey rsa:2048 -keyout client_key.pem -out client_cert.csr -nodes
        # openssl x509 -req -in client_cert.csr -CA cert.pem -CAkey key.pem -CAcreateserial -out client_cert.pem -days 365

        # Example 1: Server-side context with certificate and key
        server_context = getSSLContext(certfile="cert.pem", keyfile="key.pem", server_side=True)
        if server_context:
            print("Server SSL context created successfully.")

        # Example 2: Client-side context with CA certificate for server verification
        client_context = getSSLContext(cafile="cert.pem", server_side=False)
        if client_context:
            print("Client SSL context created successfully.")

        # Example 3: Mutual TLS (client authentication)
        mutual_tls_context = getSSLContext(certfile="client_cert.pem", keyfile="client_key.pem", cafile="cert.pem", server_side=True)
        if mutual_tls_context:
            print("Mutual TLS context created successfully.")

    except Exception as e:
        print(f"An error occurred during example usage: {e}")

