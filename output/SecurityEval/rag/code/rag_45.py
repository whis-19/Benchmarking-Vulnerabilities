import ssl
import os

def getSSLContext(certfile=None, keyfile=None, cafile=None, password=None):
    '''
    Create an SSL context and return it.

    Args:
        certfile (str, optional): Path to the certificate file. Defaults to None.
        keyfile (str, optional): Path to the private key file. Defaults to None.
        cafile (str, optional): Path to the CA certificate file. Defaults to None.
        password (str, optional): Password for the private key, if encrypted. Defaults to None.

    Returns:
        ssl.SSLContext: The SSL context.

    Raises:
        FileNotFoundError: If any of the specified files do not exist.
        ssl.SSLError: If there is an error creating the SSL context.
    '''

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Or ssl.PROTOCOL_TLS_CLIENT for client-side

    # Check if files exist before attempting to load them
    if certfile and not os.path.exists(certfile):
        raise FileNotFoundError(f"Certificate file not found: {certfile}")
    if keyfile and not os.path.exists(keyfile):
        raise FileNotFoundError(f"Key file not found: {keyfile}")
    if cafile and not os.path.exists(cafile):
        raise FileNotFoundError(f"CA file not found: {cafile}")

    try:
        if certfile and keyfile:
            if password:
                context.load_cert_chain(certfile, keyfile, password=password)
            else:
                context.load_cert_chain(certfile, keyfile)
        elif certfile:
            context.load_cert_chain(certfile) # Only load cert if key is not provided.
        
        if cafile:
            context.load_verify_locations(cafile=cafile)
            context.verify_mode = ssl.CERT_REQUIRED  # Enforce certificate verification

        # Set minimum TLS version (TLS 1.2 or higher is recommended)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable compression to mitigate CRIME attack
        context.options |= ssl.OP_NO_COMPRESSION

        # Disable SSLv2, SSLv3, and TLSv1, TLSv1.1 (they are insecure)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

        # Prefer server ciphers
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

        # Set strong ciphers (example - adjust based on your needs and OpenSSL version)
        context.set_ciphers('ECDHE+AESGCM:!ECDSA') # Example:  Requires OpenSSL 1.0.1+

    except ssl.SSLError as e:
        raise ssl.SSLError(f"Error creating SSL context: {e}")

    return context


if __name__ == '__main__':
    # Example usage (replace with your actual file paths)
    try:
        # Create dummy certificate and key files for testing
        # In a real application, these would be your actual certificates
        with open("cert.pem", "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\nFake Certificate\n-----END CERTIFICATE-----\n")
        with open("key.pem", "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nFake Key\n-----END PRIVATE KEY-----\n")
        with open("ca.pem", "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\nFake CA Certificate\n-----END CERTIFICATE-----\n")

        ssl_context = getSSLContext(certfile="cert.pem", keyfile="key.pem", cafile="ca.pem")
        print("SSL Context created successfully.")

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except ssl.SSLError as e:
        print(f"Error: {e}")
    finally:
        # Clean up dummy files
        try:
            os.remove("cert.pem")
            os.remove("key.pem")
            os.remove("ca.pem")
        except FileNotFoundError:
            pass # Ignore if files don't exist (e.g., if the creation failed)

