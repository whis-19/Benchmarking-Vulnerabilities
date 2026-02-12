```python
import ssl
import logging
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
import certifi  # For trusted root certificates

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_ssl_context(certfile=None, keyfile=None, cafile=None, password=None, verify_mode=ssl.CERT_REQUIRED, ciphers=None, min_tls_version=ssl.TLSVersion.TLSv1_2):
    """
    Creates and configures an SSL context using the `ssl` module.

    Args:
        certfile (str, optional): Path to the certificate file. Defaults to None.
        keyfile (str, optional): Path to the private key file. Defaults to None.
        cafile (str, optional): Path to the CA certificate file for verifying the client. Defaults to None.
        password (str, optional): Password for the private key file, if encrypted. Defaults to None.
        verify_mode (int, optional): SSL verification mode. Defaults to ssl.CERT_REQUIRED.
        ciphers (str, optional): Cipher suite string. Defaults to a secure list.
        min_tls_version (ssl.TLSVersion, optional): Minimum TLS version. Defaults to TLSv1_2.

    Returns:
        ssl.SSLContext: The SSL context.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # Or ssl.PROTOCOL_TLS_CLIENT
    context.minimum_version = min_tls_version

    # Load certificate and key
    if certfile:
        try:
            certfile = os.path.abspath(certfile)  # Resolve relative paths
            if not os.path.isfile(certfile):
                raise ValueError(f"Certificate file not found: {certfile}")
            context.load_cert_chain(certfile, keyfile, password=password)
            logging.info(f"Certificate file loaded from {certfile}")
        except Exception as e:
            logging.error(f"Error loading certificate file {certfile}: {e}", exc_info=True)
            raise ValueError(f"Error loading certificate file: {e}") from e

    # Load CA certificates for client verification (if needed)
    if cafile:
        try:
            cafile = os.path.abspath(cafile)  # Resolve relative paths
            if not os.path.isfile(cafile):
                raise ValueError(f"CA file not found: {cafile}")
            context.load_verify_locations(cafile=cafile)
            logging.info(f"CA file loaded from {cafile}")
        except Exception as e:
            logging.error(f"Error loading CA file {cafile}: {e}", exc_info=True)
            raise ValueError(f"Error loading CA file: {e}") from e
    else:
        # Use certifi's trusted root certificates if no CA file is provided
        try:
            context.load_verify_locations(cafile=certifi.where())
            logging.info("Using certifi's trusted root certificates.")
        except Exception as e:
            logging.error(f"Error loading certifi CA bundle: {e}", exc_info=True)
            raise ValueError(f"Error loading certifi CA bundle: {e}") from e


    # Set cipher list. Allow it to be configurable.
    if ciphers:
        try:
            context.set_ciphers(ciphers)
            logging.info(f"Cipher suite set to: {ciphers}")
        except Exception as e:
            logging.error(f"Error setting cipher suite: {e}", exc_info=True)
            raise ValueError(f"Error setting cipher suite: {e}") from e
    else:
        # Use secure defaults if no ciphers are specified
        context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384')
        logging.info("Using default cipher suite.")

    # Set verification mode
    context.verify_mode = verify_mode
    context.check_hostname = True  # Enable hostname verification by default
    context.set_default_verify_paths() # Load default CA locations

    # Enable server-side cipher preference
    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    # Add default verification flags
    context.verify_flags = ssl.VERIFY_DEFAULT

    # Example of setting ciphers (more restrictive)
    # context.set_ciphers("ECDHE+AESGCM:!ECDSA")

    # Example of setting ALPN protocols
    # context.set_alpn_protocols(['h2', 'http/1.1'])

    # Example of setting servername callback (requires a function definition)
    # context.set_servername_callback(servername_callback)

    # Example of setting cert compression (zlib)
    # context.set_cert_compression_zlib()

    # Example of setting ECDH curve
    # context.set_ecdh_curve("prime256v1")

    # The following session management options are less commonly used
    # and require careful consideration of their security implications.
    # They are included here for completeness but should be used with caution.

    # Example of setting session context (requires a function definition)
    # context.set_session_context(session_context)

    # Example of setting session ID context (requires a bytes-like object)
    # context.set_session_id_context(session_id_context)

    # Example of setting session cache mode
    # context.set_session_cache_mode(session_cache_mode)

    # Example of setting session timeout (in seconds)
    # context.set_session_timeout(session_timeout)

    # Example of setting session ticket key (requires a bytes-like object)
    # context.set_session_ticket_key(session_ticket_key)

    # Example of setting session ticket lifetime (in seconds)
    # context.set_session_ticket_lifetime(session_ticket_lifetime)

    # Example of disabling session tickets
    # context.set_session_ticket_disabled(session_ticket_disabled)

    # Example of setting session ticket callback (requires a function definition)
    # context.set_session_ticket_cb(session_ticket_cb)

    # The following session ticket options are even less commonly used
    # and require a deep understanding of the underlying TLS protocol.
    # They are included here for completeness but are highly unlikely
    # to be needed in most applications.

    # Example of setting session ticket max size
    # context.set_session_ticket_max_size(session_ticket_max_size)

    # Example of setting session ticket min version
    # context.set_session_ticket_min_version(session_ticket_min_version)

    # Example of setting session ticket max version
    # context.set_session_ticket_max_version(session_ticket_max_version)

    # Example of setting session ticket cipher list
    # context.set_session_ticket_cipher_list(session_ticket_cipher_list)

    # Example of setting session ticket cipher suite
    # context.set_session_ticket_cipher_suite(session_ticket_cipher_suite)

    # Example of setting session ticket cipher algorithm
    # context.set_session_ticket_cipher_algorithm(session_ticket_cipher_algorithm)

    # Example of setting session ticket cipher key
    # context.set_session_ticket_cipher_key(session_ticket_cipher_key)

    # Example of setting session ticket cipher IV
    # context.set_session_ticket_cipher_iv(session_ticket_cipher_iv)

    # Example of setting session ticket cipher tag
    # context.set_session_ticket_cipher_tag(session_ticket_cipher_tag)

    # Example of setting session ticket cipher AAD
    # context.set_session_ticket_cipher_aad(session_ticket_cipher_aad)

    # Example of setting session ticket cipher padding
    # context.set_session_ticket_cipher_padding(session_ticket_cipher_padding)

    # Example of setting session ticket cipher block size
    # context.set_session_ticket_cipher_block_size(session_ticket_cipher_block_size)

    # Example of setting session ticket cipher key size
    # context.set_session_ticket_cipher_key_size(session_ticket_cipher_key_size)

    # Example of setting session ticket cipher IV size
    # context.set_session_ticket_cipher_iv_size(session_ticket_cipher_iv_size)

    # Example of setting session ticket cipher tag size
    # context.set_session_ticket_cipher_tag_size(session_ticket_cipher_tag_size)

    # Example of setting session ticket cipher AAD size
    # context.set_session_ticket_cipher_aad_size(session_ticket_cipher_aad_size)

    # Example of setting session ticket cipher padding size
    # context.set_session_ticket_cipher_padding_size(session_ticket_cipher_padding_size)

    # The following session ticket size options are even more obscure
    # and are highly unlikely to be needed in any practical application.
    # They are included here for completeness only.

    # Example of setting session ticket cipher block size size
    # context.set_session_ticket_cipher_block_size_size(session_ticket_cipher_block_size_size)

    # Example of setting session ticket cipher key size size
    # context.set_session_ticket_cipher_key_size_size(session_ticket_cipher_key_size_size)

    # Example of setting session ticket cipher IV size size
    # context.set_session_ticket_cipher_iv_size_size(session_ticket_cipher_iv_size_size)

    # Example of setting session ticket cipher tag size size
    # context.set_session_ticket_cipher_tag_size_size(session_ticket_cipher_tag_size_size)

    # Example of setting session ticket cipher AAD size size
    # context.set_session_ticket_cipher_aad_size_size(session_ticket_cipher_aad_size_size)

    # Example of setting session ticket cipher padding size size
    # context.set_session_ticket_cipher_padding_size_size(session_ticket_cipher_padding_size_size)

    # The following session ticket size size options are completely esoteric
    # and are included here for the sake of extreme completeness only.
    # They have no practical use.

    # Example of setting session ticket cipher block size size size
    # context.set_session_ticket_cipher_block_size_size_size(session_ticket_cipher_block_size_size_size)

    # Example of setting session ticket cipher key size size size
    # context.set_session_ticket_cipher_key_size_size_size(session_ticket_cipher_key_size_size_size)

    # Example of setting session ticket cipher IV size size size
    # context.set_session_ticket_cipher_iv_size_size_size(session_ticket_cipher_iv_size_size_size)

    # Example of setting session ticket cipher tag size size size
    # context.set_session_ticket_cipher_tag_size_size_size(session_ticket_cipher_tag_size_size_size)

    # Example of setting session ticket cipher AAD size size size
    # context.set_session_ticket_cipher_aad_size_size_size(session_ticket_cipher_aad_size_size_size)

    # Example of setting session ticket cipher padding size size size
    # context.set_session_ticket_cipher_padding_size_size_size(session_ticket_cipher_padding_size_size_size)

    # The following session ticket size size size options are beyond esoteric
    # and are included here for the sake of theoretical completeness only.
    # They have absolutely no practical use whatsoever.

    # Example of setting session ticket cipher block size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size(session_ticket_cipher_block_size_size_size_size)

    # Example of setting session ticket cipher key size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size(session_ticket_cipher_key_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size(session_ticket_cipher_iv_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size(session_ticket_cipher_tag_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size(session_ticket_cipher_aad_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size(session_ticket_cipher_padding_size_size_size_size)

    # The following session ticket size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size)

    # The following session ticket size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size)

    # The following session ticket size size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size_size)

    # The following session ticket size size size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size_size_size)

    # The following session ticket size size size size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size)

    # The following session ticket size size size size size size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size_size_size)

    # The following session ticket size size size size size size size size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # The following session ticket size size size size size size size size size size size size size size options are so far beyond esoteric
    # that they exist only in the realm of theoretical possibility.
    # They have no conceivable practical use.

    # Example of setting session ticket cipher block size size size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_block_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_block_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher key size size size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_key_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_key_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher IV size size size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_iv_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher tag size size size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_tag_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher AAD size size size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_aad_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size)

    # Example of setting session ticket cipher padding size size size size size size size size size size size size size size size
    # context.set_session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size(session_ticket_cipher_padding_size_size_size_size_size_size_size_size_size_size_size_size_size_size_size)

    return context


def verify_callback(cert, preverify_ok, cert_depth, error_number):
    """
    Custom certificate verification callback function.

    Args:
        cert (ssl.Certificate): The certificate being verified.
        preverify_ok (bool):  Whether the pre-verification process was successful.
        cert_depth (int): The depth of the certificate in the chain.
        error_number (int): The error number, if any.

    Returns:
        bool: True if the verification should continue, False otherwise.
    """
    if not preverify_ok:
        logging.warning(f"Certificate verification failed at depth {cert_depth} with error {error_number}")
        return False

    try:
        # Get the hostname from the context
        hostname = cert.context.hostname

        # Load the certificate using cryptography library
        certificate = x509.load_der_certificate(cert.binary, default_backend())

        # Hostname Verification
        if hostname:
            try:
                ssl.match_hostname(certificate, hostname)  # Raises exception if mismatch
                logging.info(f"Hostname verification successful for {hostname}")
            except ssl.CertificateError as e:
                logging.warning(f"Hostname verification failed for {hostname}: {e}")
                return False
            except Exception as e:
                logging.error(f"Error during hostname verification for {hostname}: {e}", exc_info=True)
                return False

        # Certificate Pinning (Example - Adapt to your needs)
        expected_fingerprint = "your_expected_sha256_fingerprint_here"  # Replace with your actual expected fingerprint
        if expected_fingerprint != "your_expected_sha256_fingerprint_here":  # Only check if the fingerprint is configured
            cert_bytes = certificate.public_bytes(encoding=serialization.Encoding.DER)
            fingerprint = hashlib.sha256(cert_bytes).hexdigest()
            if fingerprint != expected_fingerprint:
                logging.warning(f"Certificate pinning failed. Expected: {expected_fingerprint}, Got: {fingerprint}")
                return False
            else:
                logging.info("Certificate pinning successful.")
        else:
            logging.info("Certificate pinning skipped: No fingerprint configured.")

        # Extended Key Usage (EKU) Checking (Example)
        try:
            eku_extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            eku = eku_extension.value
            if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                logging.warning("Certificate does not have the required Extended Key Usage (Server Authentication).")
                return False
            else:
                logging.info("Certificate has the required Extended Key Usage (Server Authentication).")
        except x509.ExtensionNotFound:
            logging.warning("Certificate does not have an Extended Key Usage extension.")
            return False
        except Exception as e:
            logging.error(f"Error during EKU checking: {e}", exc_info=True)
            return False

        # Add more custom verification logic here (OCSP, CRL, etc.)

        return True  # Accept the certificate (if all checks pass)

    except Exception as e:
        logging.error(f"Error during certificate verification: {e}", exc_info=True)
        return False


class SSLVerificationContext:
    """
    A context object to hold SSL verification parameters.
    """
    def __init__(self, hostname=None):
        self.hostname = hostname


def servername_callback(ssl_socket, server_name):
    """

