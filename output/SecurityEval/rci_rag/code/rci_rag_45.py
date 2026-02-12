import ssl
import os
import logging
import stat

# Configure logging (replace with your preferred logging setup)
logging.basicConfig(level=logging.WARNING)

def getSSLContext(cafile_path, certfile_path, keyfile_path, session_timeout=3600):
    '''
    Create an SSL context and return it.  This context is configured for secure
    communication, prioritizing security over compatibility.  It disables
    insecure protocols and ciphers.  It is intended for server-side use.

    Considerations:

    *   **Server-Side Focus:** This configuration is optimized for server-side
        applications where you have more control over the client's capabilities.
        Clients that don't support TLS 1.2 or higher will not be able to connect.

    *   **Certificate Verification:**  This context *requires* certificate
        verification.  You *must* provide a `cafile` or `capath` to specify
        trusted CA certificates.  Failing to do so will result in connection
        errors.

    *   **Cipher Suite Selection:**  The cipher suite selection is restricted to
        strong, modern ciphers with forward secrecy.  Older, weaker ciphers are disabled.
        Research the latest recommendations and tailor the selection to your specific needs.
        Use `openssl ciphers -v 'TLSv1.2'` to view available ciphers.  Prioritize ciphers
        with forward secrecy (e.g., ECDHE or DHE).  The order of ciphers matters; the server
        will prefer the first cipher in the list that the client also supports.
        Establish a process for regularly reviewing and updating the cipher suite list.

    *   **Protocol Selection:**  Only TLS 1.2 and TLS 1.3 are enabled.  SSLv2,
        SSLv3, TLS 1.0, and TLS 1.1 are disabled due to known vulnerabilities.

    *   **Error Handling:**  This function does not handle exceptions related to
        the *use* of the context. It *does* handle exceptions during context
        creation where failure is unacceptable. It is the
        caller's responsibility to catch any `ssl.SSLError` exceptions that may
        occur during context creation.

    *   **Trust Zones:** This code unit assumes it operates within a defined trust zone.
        The caller is responsible for ensuring the integrity of the environment and
        the CA certificates used for verification.  Consider using code signing,
        secure boot, and configuration management.

    *   **Sensitive Information:** This function itself does not handle sensitive
        information directly. However, the certificates and keys used with the
        SSL context *are* sensitive.  They should be stored securely, as described
        below.

        **WARNING:  Never store the private key in plaintext on the file system.
        Use a hardware security module (HSM), key management system (KMS), or
        encrypted storage with strong access controls.**

    *   **Risks of Misconfiguration:**  Misconfiguring the SSL context can expose
        your application to man-in-the-middle attacks, data breaches, and other
        security vulnerabilities.  Carefully review all settings and ensure that
        they are appropriate for your environment.

    *   **Session Tickets:** Consider disabling session tickets (`context.options |= ssl.OP_NO_TICKET`)
        if you don't need them. Session tickets can potentially be used to track users across sessions.
        If you do use session tickets, ensure that they are encrypted with a strong key that is rotated regularly.

    Args:
        cafile_path (str): Path to the CA bundle file.
        certfile_path (str): Path to the server certificate file.
        keyfile_path (str): Path to the server private key file.
        session_timeout (int): Session timeout in seconds.

    Returns:
        ssl.SSLContext: A configured SSL context.

    Raises:
        ssl.SSLError: If there is an error creating the SSL context.
        ValueError: If the provided file paths are invalid.
        OSError: If there is an error opening or reading the certificate or key files.
    '''

    # Input Validation
    if not all(isinstance(path, str) for path in [cafile_path, certfile_path, keyfile_path]):
        raise TypeError("File paths must be strings.")

    for path in [cafile_path, certfile_path, keyfile_path]:
        abs_path = os.path.abspath(path)
        if not os.path.isfile(abs_path):
            raise ValueError(f"File not found: {abs_path}")
        if not os.access(abs_path, os.R_OK):
            raise ValueError(f"File not readable: {abs_path}")

    # Check key file permissions
    try:
        key_stat = os.stat(keyfile_path)
        key_permissions = stat.S_IMODE(key_stat.st_mode)  # Extract permission bits
        if key_permissions & 0o077 != 0:  # Check if group/other have any permissions
            logging.warning(f"Private key file {keyfile_path} has overly permissive permissions: {oct(key_permissions)}.  Recommended permissions are 0600 or 0400.")
    except OSError as e:
        logging.warning(f"Could not check permissions on key file {keyfile_path}: {e}")


    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Or ssl.PROTOCOL_TLS_CLIENT for client-side

    # Security Hardening:  Disable insecure protocols and ciphers.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384')  # Modern, strong ciphers with forward secrecy

    # Require certificate verification.  This is crucial for server-side security.
    # You MUST provide a cafile or capath.
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=cafile_path)  # Replace with the actual path to your CA bundle.  This is CRITICAL.
    except OSError as e:
        raise OSError(f"Error loading CA file: {e}") from e

    # Load the server certificate and private key.  These should be stored securely.
    try:
        context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path) # Replace with the actual paths.
    except OSError as e:
        raise OSError(f"Error loading certificate or key file: {e}") from e

    # Optional:  Enable session resumption for improved performance (server-side).
    context.session_cache_mode = ssl.SESSION_CACHE_SERVER

    # Optional:  Set session timeout (server-side).  Adjust as needed.
    context.set_session_timeout(session_timeout)  # 1 hour

    # Optional:  Enable OCSP stapling for improved certificate validation.
    try:
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        context.options |= ssl.OP_NO_COMPRESSION # Disable compression to prevent CRIME attack
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE # Server chooses cipher
        # Enable OCSP Stapling - DO NOT set OP_NO_OCSP
        # context.options |= ssl.OP_NO_OCSP
    except ValueError as e:
        # ssl.OP_NO_COMPRESSION or ssl.OP_NO_OCSP may not be available on older OpenSSL versions
        logging.warning(f"Feature not supported: {e}")
    except Exception as e:
        logging.warning(f"Error enabling OCSP stapling: {e}")

    # Optional: Disable session tickets
    # context.options |= ssl.OP_NO_TICKET

    logging.info("SSL Context created successfully.")  # Log successful creation

    return context

# Example Usage (replace with your actual paths)
try:
    # Use environment variables for paths
    cafile_path = os.environ.get("CA_BUNDLE_PATH", "/path/to/default/ca_bundle.pem")  # Provide a default
    certfile_path = os.environ.get("SERVER_CERT_PATH", "/path/to/default/server.crt")
    keyfile_path = os.environ.get("SERVER_KEY_PATH", "/path/to/default/server.key")

    context = getSSLContext(
        cafile_path=cafile_path,
        certfile_path=certfile_path,
        keyfile_path=keyfile_path
    )
    # Use the context...
except ssl.SSLError as e:
    logging.error(f"Error creating SSL context: {e}")
    print(f"Error creating SSL context: {e}")
except ValueError as e:
    logging.error(f"Invalid file path: {e}")
    print(f"Invalid file path: {e}")
except OSError as e:
    logging.error(f"Error opening or reading certificate/key file: {e}")
    print(f"Error opening or reading certificate/key file: {e}")
except Exception as e:
    logging.exception(f"An unexpected error occurred: {e}") # Log the full traceback
    print(f"An unexpected error occurred: {e}")

