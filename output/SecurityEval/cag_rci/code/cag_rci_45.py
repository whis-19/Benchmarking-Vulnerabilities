import ssl
import os
import getpass
import logging
import socket  # Import socket for example usage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def getSSLContext(certfile=None, keyfile=None, cafile=None, password=None, is_server=False):
    """
    Create a secure SSL context.

    Args:
        certfile (str, optional): Path to the certificate file (PEM format). Defaults to None.
        keyfile (str, optional): Path to the private key file (PEM format). Defaults to None.
        cafile (str, optional): Path to the CA certificate file (PEM format) for verifying client certificates. Defaults to None.
        password (str, optional): Password for decrypting the private key, if encrypted. Defaults to None.
        is_server (bool, optional):  Whether to create a server-side SSL context. Defaults to False.

    Returns:
        ssl.SSLContext: A configured SSL context.

    Raises:
        FileNotFoundError: If any of the specified files (certfile, keyfile, cafile) do not exist.
        ssl.SSLError: If there are issues loading the certificates or key.
        ValueError: If certfile is provided without keyfile, or vice versa.

    Security Considerations:
    - **Certificate and Key Management:**  Store certificate and key files securely.  Avoid hardcoding paths directly in the code.  Use environment variables or configuration files (e.g., YAML, JSON). Consider using libraries like PyYAML, python-decouple, or Dynaconf for configuration management.
    - **Permissions:** Ensure the certificate and key files have appropriate permissions (e.g., read-only for the user running the application).
    - **Password Protection:** If the private key is password-protected, handle the password securely.  Avoid storing it in plain text.  Consider using a secure password manager or prompting the user for the password.  Ideally, generate an unencrypted key file or cache the decrypted key in memory.
    - **CA Certificates:**  Use a trusted CA certificate bundle (cafile) to verify the authenticity of client certificates.  Keep the CA bundle up-to-date.
    - **SSL/TLS Version:**  Explicitly specify the minimum TLS version to prevent the use of older, insecure protocols.
    - **Cipher Suites:**  Configure cipher suites to restrict the allowed encryption algorithms to strong ones.  However, be mindful of compatibility with clients.  Prioritize Perfect Forward Secrecy (PFS).
    - **Hostname Verification:**  Enable hostname verification to prevent man-in-the-middle attacks.  This is especially important for client-side connections.
    - **Error Handling:**  Implement robust error handling to catch exceptions during SSL context creation and certificate loading.  Log errors appropriately using `logger.exception()` to include the full traceback.
    - **File Permissions:** Ensure certificate and key files have restrictive permissions (e.g., read-only for the user running the application).
    """

    if is_server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True  # Always enable for client connections

    # Set minimum TLS version
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Recommended minimum
    # Consider using TLSv1_3 if supported: context.minimum_version = ssl.TLSVersion.TLSv1_3

    # Load certificates and key
    if certfile and keyfile:
        if not os.path.exists(certfile):
            raise FileNotFoundError(f"Certificate file not found: {certfile}")
        if not os.path.exists(keyfile):
            raise FileNotFoundError(f"Key file not found: {keyfile}")

        try:
            context.load_cert_chain(certfile, keyfile, password=password)
        except ssl.SSLError as e:
            raise ssl.SSLError(f"Error loading certificate chain: {e}")

        context.verify_mode = ssl.CERT_REQUIRED  # Require client certificates
        if cafile:
            if not os.path.exists(cafile):
                raise FileNotFoundError(f"CA file not found: {cafile}")
            try:
                context.load_verify_locations(cafile=cafile)
            except ssl.SSLError as e:
                raise ssl.SSLError(f"Error loading CA file: {e}")
        else:
            # If no CA file is provided, use the system's default CA certificates.
            context.load_default_certs()

    elif certfile or keyfile:
        raise ValueError("Both certfile and keyfile must be provided together.")
    else:
        # If no certfile and keyfile are provided, use the system's default CA certificates for client-side connections.
        context.load_default_certs()


    # Configure cipher suites (optional, but recommended for security)
    # Example:  context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384')
    # Choose cipher suites based on your security requirements and client compatibility.
    # Prioritize PFS and strong encryption algorithms.  Consult Mozilla SSL Configuration Generator.
    context.set_ciphers(
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:'  # Strongest, preferred
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:'    # Strongest, RSA fallback
        'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:' # Modern, good performance
        'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:'   # Modern, good performance
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:'  # Strong, good compatibility
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:'    # Strong, good compatibility
        'TLS_AES_256_GCM_SHA384:'                   # AES-256, if ECDHE not possible
        'TLS_AES_128_GCM_SHA256:'                   # AES-128, if ECDHE not possible
        '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK' # Exclude weak/deprecated
    )

    return context


if __name__ == '__main__':
    # Example usage (REPLACE THESE WITH YOUR ACTUAL FILE PATHS!)
    # WARNING: The following file paths are placeholders.  You *must* replace them
    # with the actual paths to your certificate, key, and CA files.  Failing to
    # do so will result in errors or insecure connections.
    try:
        # Example with certificate and key files
        cert_path = os.environ.get("SSL_CERT_FILE")  # Replace with your certificate path
        key_path = os.environ.get("SSL_KEY_FILE")  # Replace with your key path
        ca_path = os.environ.get("SSL_CA_FILE") # Replace with your CA certificate path (optional)

        # Ensure the files exist before calling getSSLContext
        if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
            # Get password securely
            password = getpass.getpass("Enter the password for the private key (if any): ")
            ssl_context = getSSLContext(certfile=cert_path, keyfile=key_path, cafile=ca_path, password=password)
            logger.info("SSL context created successfully with certificate and key files.")
        else:
            logger.warning("Certificate or key file not found.  Using default SSL context.")
            ssl_context = getSSLContext() # Create a default context if files are missing.
            logger.info("SSL context created successfully with default settings.")


        # Example without certificate and key files (using default settings)
        # ssl_context = getSSLContext()
        # print("SSL context created successfully with default settings.")


        # You can now use the ssl_context in your socket connections.
        # For example:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with ssl_context.wrap_socket(sock, server_hostname="example.com") as ssock:
                    try:
                        ssock.connect(("example.com", 443))
                        print(ssock.version())
                    except socket.gaierror as e:
                        logger.error(f"Socket connection error: Could not resolve hostname: {e}")
                    except ConnectionRefusedError as e:
                        logger.error(f"Socket connection error: Connection refused: {e}")
                    except ssl.SSLError as e:
                        logger.error(f"SSL handshake error: {e}")
                    except Exception as e:
                        logger.exception("Error during socket connection:")
        except Exception as e:
            logger.exception("Error creating socket:")


    except FileNotFoundError as e:
        logger.error(f"Error: {e}")
    except ssl.SSLError as e:
        logger.error(f"SSL Error: {e}")
    except ValueError as e:
        logger.error(f"Value Error: {e}")
    except Exception as e:
        logger.exception("An unexpected error occurred:") # Log the full traceback

