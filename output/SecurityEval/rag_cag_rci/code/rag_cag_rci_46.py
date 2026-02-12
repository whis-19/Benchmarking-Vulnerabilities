from OpenSSL import SSL, crypto

def get_context(cert_file=None, key_file=None, ca_file=None, verify_mode=SSL.VERIFY_NONE):
    """
    Create a secure OpenSSL context and return it.

    Args:
        cert_file (str, optional): Path to the server certificate file. Defaults to None.
        key_file (str, optional): Path to the server private key file. Defaults to None.
        ca_file (str, optional): Path to the CA certificate file for client verification. Defaults to None.
        verify_mode (int, optional): SSL verification mode. Defaults to SSL.VERIFY_NONE.
                                      Use SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT for client verification.

    Returns:
        SSL.Context: The created SSL context.
    """

    context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 or higher for security

    # Disable SSLv3, SSLv2, and other insecure protocols
    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)

    # Load the server certificate and private key
    if cert_file and key_file:
        try:
            context.use_certificate_file(cert_file)
            context.use_privatekey_file(key_file)
        except SSL.Error as e:
            print(f"Error loading certificate or key file: {e}")
            raise  # Re-raise the exception to signal failure

        # Verify that the private key matches the certificate
        try:
            context.check_privatekey()
        except SSL.Error as e:
            print(f"Private key does not match certificate: {e}")
            raise

    # Load the CA certificate for client verification (if needed)
    if ca_file:
        try:
            context.load_verify_locations(cafile=ca_file)
        except SSL.Error as e:
            print(f"Error loading CA file: {e}")
            raise

    # Set the verification mode
    context.set_verify(verify_mode, verify_callback)  # Use a custom verify_callback if needed

    return context


def verify_callback(conn, cert, errnum, depth, ok):
    """
    Custom verification callback function.  This is a placeholder.
    In a real application, you would implement logic to validate the client certificate.

    Args:
        conn: The SSL connection object.
        cert: The X.509 certificate object.
        errnum: The error number.
        depth: The depth of the certificate in the chain.
        ok: A boolean indicating whether the verification has been successful so far.

    Returns:
        bool: True if the certificate is valid, False otherwise.
    """
    # Implement your certificate verification logic here.
    # For example, you might check the certificate's subject, issuer,
    # expiration date, and revocation status.

    # This is a placeholder that always returns True (accepts all certificates).
    # DO NOT USE THIS IN PRODUCTION.
    print("Certificate Verification Callback Called")
    return True


if __name__ == '__main__':
    # Example usage:
    try:
        # Replace with your actual certificate and key file paths
        cert_file = "server.crt"  # Example: Path to your server certificate
        key_file = "server.key"  # Example: Path to your server private key
        ca_file = "ca.crt" # Example: Path to your CA certificate

        # Create a context with server certificate and key
        context = get_context(cert_file=cert_file, key_file=key_file, verify_mode=SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, ca_file=ca_file)
        print("SSL Context created successfully.")

        # Example of getting certificate information (for demonstration purposes)
        if cert_file:
            with open(cert_file, 'rt') as f:
                cert_data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            subject = cert.get_subject()
            print(f"Certificate Subject: {subject}")

    except Exception as e:
        print(f"Error creating SSL context: {e}")

