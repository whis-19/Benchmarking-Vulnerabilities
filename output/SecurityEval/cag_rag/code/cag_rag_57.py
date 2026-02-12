# Example usage:

# Assume you have a certificate and its known hash (e.g., retrieved from a database)
certificate = "This is the certificate data"
# In a real application, you would retrieve the combined hash (salt + hash) from storage
# For this example, we'll generate it once and store it.  This is ONLY for demonstration.
# In a real application, you would *never* hardcode the hash.
salt = os.urandom(16)
hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate.encode('utf-8'), salt, 100000)
known_hash = salt + hashed_certificate # Store this combined hash in your database

# Now, when you need to verify the certificate:
is_valid = certificate_matches(certificate, known_hash)

if is_valid:
    print("Certificate is valid!")
else:
    print("Certificate is invalid!")

