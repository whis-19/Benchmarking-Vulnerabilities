import ssl

def get_ctx():
    '''
    Create a SSL context with stdlib settings.
    '''
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # You can customize the context further, e.g., by specifying the minimum TLS version:
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Or TLSv1_3 for even stronger security

    # Consider disabling compression to mitigate certain attacks (e.g., BREACH)
    context.options |= ssl.OP_NO_COMPRESSION

    #  If you need to load a specific CA certificate:
    # context.load_verify_locations("path/to/ca.pem")

    # If you need to load a client certificate and key:
    # context.load_cert_chain("path/to/cert.pem", "path/to/key.pem")

    return context


# Example usage (not for production without further hardening):
if __name__ == '__main__':
    ctx = get_ctx()
    print(f"SSL Context created with minimum TLS version: {ctx.minimum_version}")
    print(f"SSL Context options: {ctx.options}")


# Security Considerations and Guidelines Implementation:

# 1. Trust Zones:  This code unit itself doesn't explicitly manage trust zones.  However, the *use* of this SSL context *must* be within a system that has a well-defined trust model.  For example, if this context is used in a server, the server's overall security architecture needs to consider trust boundaries.  The `ssl.create_default_context` function helps by providing a reasonable default, but it's not a complete solution for trust management.  The caller of `get_ctx()` is responsible for ensuring the context is used securely within its trust zone.

# 2. Cookies: This code unit does *not* construct cookies.  This guideline is not applicable here.

# 3. Sensitive Information: This code unit does *not* directly handle sensitive information.  However, it's crucial that any application *using* this SSL context to transmit sensitive data (e.g., passwords, API keys) adheres to the guidelines:
#    - Store sensitive information in an encrypted configuration file or database with restricted access.
#    - Apply strong one-way hashes to passwords (e.g., using bcrypt or Argon2).
#    - Store password hashes in a configuration file or database with appropriate access control.
#    - Encrypt usernames and passwords.

# 4. Password Hashing:  This code unit does *not* handle password hashing.  This guideline is not applicable here.

# 5. Password Hash Storage: This code unit does *not* handle password hash storage. This guideline is not applicable here.

# 6. Username/Password Encryption: This code unit does *not* handle username/password encryption. This guideline is not applicable here.

# 7. HTTP Request Allowlist: This code unit does *not* handle HTTP requests or webpage construction. This guideline is not applicable here.

# 8. HTTP Request Validation: This code unit does *not* handle HTTP requests. This guideline is not applicable here.

# 9. HttpOnly Cookie: This code unit does *not* handle cookies. This guideline is not applicable here.

# 10. HTTP Header Encoding: This code unit does *not* handle HTTP headers. This guideline is not applicable here.

# Important Notes:

# * **Certificate Verification:**  The `ssl.create_default_context(ssl.Purpose.SERVER_AUTH)` function enables certificate verification by default.  This is *essential* for security.  Do *not* disable certificate verification unless you have a very specific and well-understood reason to do so (and even then, it's generally a bad idea).

# * **TLS Version:**  Always use the highest TLS version supported by your environment and the clients you need to support.  TLS 1.2 is the minimum acceptable version, and TLS 1.3 is preferred.

# * **Cipher Suites:**  You can further customize the SSL context by specifying the cipher suites to use.  However, be very careful when doing this, as choosing weak cipher suites can significantly weaken your security.  It's generally best to rely on the default cipher suites provided by the SSL library.  If you *must* customize cipher suites, consult with a security expert.

# * **Error Handling:**  The code above doesn't include explicit error handling.  In a production environment, you should add `try...except` blocks to handle potential exceptions that might occur during SSL context creation or usage.

# * **Key Management:**  If you're loading a client certificate and key, ensure that the key is stored securely and that access to it is restricted.

# * **Regular Updates:** Keep your Python installation and the `ssl` module up to date to benefit from the latest security patches and improvements.

# * **Testing:** Thoroughly test your SSL configuration to ensure that it's working as expected and that it's not vulnerable to known attacks.  Use tools like `nmap` or online SSL testing services to verify your configuration.

# * **Documentation:**  Refer to the official Python `ssl` module documentation for the most up-to-date information and best practices: https://docs.python.org/3/library/ssl.html

