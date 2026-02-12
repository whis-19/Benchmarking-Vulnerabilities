import secrets
    import base64
    from cryptography.fernet import Fernet

    print("FLASK_SECRET_KEY:", secrets.token_hex(16))
    print("FERNET_KEY:", Fernet.generate_key().decode())
    print("HMAC_KEY:", base64.b64encode(secrets.token_bytes(32)).decode())

