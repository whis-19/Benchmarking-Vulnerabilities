from OpenSSL import SSL

def getContext():
    '''
    Create an OpenSSL context and return it.
    '''
    context = SSL.Context(SSL.TLSv1_2_METHOD)  # Use TLSv1.2 or higher for security
    # Consider using SSL.TLS_METHOD for maximum compatibility, but be aware of potential vulnerabilities
    # in older TLS versions.  TLSv1.3 is preferred if available.

    # Load certificate and private key (replace with your actual paths)
    # It's crucial to store these securely and restrict access.
    try:
        context.use_privatekey_file("path/to/your/private.key")
        context.use_certificate_file("path/to/your/certificate.crt")

        # Verify the private key corresponds to the certificate
        context.check_privatekey()

    except SSL.Error as e:
        print(f"Error loading certificate or key: {e}")
        # Handle the error appropriately, e.g., raise an exception or log the error and exit.
        raise  # Re-raise the exception to stop execution if the context is essential.

    # Optional: Configure SSL context options for enhanced security
    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1) # Disable older SSL/TLS versions
    context.set_options(SSL.OP_SINGLE_DH_USE) # Use ephemeral Diffie-Hellman keys
    context.set_options(SSL.OP_CIPHER_SERVER_PREFERENCE) # Server chooses cipher
    # Set ciphersuite (choose a strong ciphersuite)
    context.set_cipher_list('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384')


    # Optional: Configure client certificate verification
    # context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback) # Enable client certificate verification
    # You'll need to define a verify_callback function to handle client certificate verification.

    return context


# Example usage (replace with your actual paths and logic)
if __name__ == '__main__':
    try:
        ctx = getContext()
        print("SSL Context created successfully.")
        # Now you can use the context to create SSL connections.
    except Exception as e:
        print(f"Failed to create SSL context: {e}")

