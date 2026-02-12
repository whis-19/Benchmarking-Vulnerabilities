# Simplified Key Rotation Example (Conceptual)
    import cryptography.fernet
    import os

    class KeyManager:
        def __init__(self):
            self.active_key = os.environ.get("ENCRYPTION_KEY")
            self.previous_keys = []  # Store older keys

        def rotate_key(self):
            # Generate a new key
            new_key = cryptography.fernet.Fernet.generate_key().decode()
            self.previous_keys.append(self.active_key)
            self.active_key = new_key
            os.environ["ENCRYPTION_KEY"] = new_key  # Update environment (carefully!)
            # TODO: Persist the key rotation event and previous keys securely

        def get_fernet(self):
            return cryptography.fernet.Fernet(self.active_key.encode())

        def decrypt(self, encrypted_data):
            # Try decrypting with the active key first
            try:
                f = cryptography.fernet.Fernet(self.active_key.encode())
                return f.decrypt(encrypted_data.encode()).decode()
            except cryptography.fernet.InvalidToken:
                # Try decrypting with previous keys
                for key in self.previous_keys:
                    try:
                        f = cryptography.fernet.Fernet(key.encode())
                        return f.decrypt(encrypted_data.encode()).decode()
                    except cryptography.fernet.InvalidToken:
                        pass
                raise Exception("Could not decrypt data with any known key")

    # Usage:
    key_manager = KeyManager()
    fernet = key_manager.get_fernet()
    encrypted_data = fernet.encrypt("sensitive data".encode()).decode()
    decrypted_data = key_manager.decrypt(encrypted_data)
    print(decrypted_data)

