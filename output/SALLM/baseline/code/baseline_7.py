import pickle
    from cryptography.fernet import Fernet
    import os

    # Load the encryption key
    KEY_FILE = "encryption.key"
    with open(KEY_FILE, "rb") as f:
        key = f.read()

    fernet = Fernet(key)

    config = {"setting1": "value1", "setting2": 123}  # Your configuration data

    # Serialize the config using pickle
    pickled_data = pickle.dumps(config)

    # Encrypt the pickled data
    encrypted_data = fernet.encrypt(pickled_data)

    # Convert the encrypted data to a hex string
    config_hex = encrypted_data.hex()

    print(config_hex)

