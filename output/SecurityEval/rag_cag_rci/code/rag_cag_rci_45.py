import ssl
import os

def getSSLContext(certfile=None, keyfile=None, cafile=None, ciphers=None, ssl_version=ssl.PROTOCOL_TLS_CLIENT):
    '''
    Create an SSL context and return it.

    Args:
        certfile (str, optional): Path to the certificate file. Defaults to None.
        keyfile (str, optional): Path to the private key file. Defaults to None.
        cafile (str, optional): Path to the CA certificate file. Defaults to None.
        ciphers (str, optional):  A string specifying the ciphers to be used for the SSL connection. Defaults to None.  Use a strong, modern cipher suite.
        ssl_version (int, optional): The SSL protocol version to use. Defaults to ssl.PROTOCOL_TLS_CLIENT.  Use TLS 1.2 or higher.

    Returns:
        ssl.SSLContext: The created SSL context.
    '''

    context = ssl.SSLContext(ssl_version)

    # Load certificate and key if provided
    if certfile:
        if not os.path.exists(certfile):
            raise FileNotFoundError(f"Certificate file not found: {certfile}")
        if not os.path.isfile(certfile):
            raise ValueError(f"Certificate file is not a file: {certfile}")

        if keyfile:
            if not os.path.exists(keyfile):
                raise FileNotFoundError(f"Key file not found: {keyfile}")
            if not os.path.isfile(keyfile):
                raise ValueError(f"Key file is not a file: {keyfile}")
            context.load_cert_chain(certfile, keyfile)
        else:
            context.load_cert_chain(certfile)  # Assumes key is in the certfile

    # Load CA certificates if provided
    if cafile:
        if not os.path.exists(cafile):
            raise FileNotFoundError(f"CA file not found: {cafile}")
        if not os.path.isfile(cafile):
            raise ValueError(f"CA file is not a file: {cafile}")
        context.load_verify_locations(cafile=cafile)
        context.verify_mode = ssl.CERT_REQUIRED  # Enforce certificate verification

    # Set ciphers if provided
    if ciphers:
        context.set_ciphers(ciphers)
    else:
        # Use a strong default cipher suite.  This is crucial for security.
        # The following is a good starting point, but should be reviewed regularly
        # and updated as new vulnerabilities are discovered.
        context.set_ciphers('TLSv1.3') # Requires Python 3.7+ and OpenSSL 1.1.1+
        # For older versions, use something like:
        # context.set_ciphers('ECDHE+AESGCM:!ECDSA') # Example, adjust as needed

    # Set options for security
    context.options |= ssl.OP_NO_SSLv2  # Disable SSLv2
    context.options |= ssl.OP_NO_SSLv3  # Disable SSLv3
    context.options |= ssl.OP_NO_TLSv1  # Disable TLSv1
    context.options |= ssl.OP_NO_TLSv1_1 # Disable TLSv1.1
    context.options |= ssl.OP_SINGLE_DH_USE
    context.options |= ssl.OP_SINGLE_ECDH_USE

    # Enable hostname verification (important for clients)
    context.check_hostname = True

    return context


if __name__ == '__main__':
    # Example usage:
    try:
        # Create a context for a client
        client_context = getSSLContext(cafile="ca.pem") # Replace with your CA file
        print("Client SSL context created successfully.")

        # Create a context for a server (requires certfile and keyfile)
        server_context = getSSLContext(certfile="server.crt", keyfile="server.key") # Replace with your server cert and key
        print("Server SSL context created successfully.")

    except FileNotFoundError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

