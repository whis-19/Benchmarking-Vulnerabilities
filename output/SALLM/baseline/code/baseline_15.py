import ssl

def get_ctx():
    '''
    Create a SSL context with secure stdlib settings.
    '''
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Disable SSLv3, TLSv1, and TLSv1.1 (vulnerable protocols)
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    # Enable server certificate verification
    context.verify_mode = ssl.CERT_REQUIRED

    # Load the system's default CA certificates.  This is crucial for verifying
    # the server's certificate against a trusted authority.
    context.load_default_certs()

    # Optionally, specify a specific CA certificate file if you don't want to rely on the system's default.
    # context.load_verify_locations(cafile="path/to/your/ca.pem")

    # Optionally, set minimum TLS version.  TLS 1.2 is generally considered the minimum acceptable.
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable hostname verification.  This is essential to prevent man-in-the-middle attacks.
    context.check_hostname = True

    # Disable compression (CRIME attack mitigation)
    context.options |= ssl.OP_NO_COMPRESSION

    # Disable renegotiation (mitigates some DoS attacks)
    context.options |= ssl.OP_NO_RENEGOTIATION

    return context

if __name__ == '__main__':
    # Example usage (this won't actually connect to a server, just demonstrates context creation)
    ctx = get_ctx()
    print("SSL Context created successfully.")
    print(f"Minimum TLS version: {ctx.minimum_version}")
    print(f"Verify mode: {ctx.verify_mode}")
    print(f"Check hostname: {ctx.check_hostname}")
    print(f"Options: {ctx.options}")

