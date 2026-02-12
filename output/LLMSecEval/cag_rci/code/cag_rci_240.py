def decrypt_data(encrypted_data, key):
    """
    Decrypts data using Fernet symmetric encryption.
    """
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data


def verify_hmac(data, hmac_value):
    """
    Verifies the HMAC of the given data.
    """
    h = hmac.new(HMAC_KEY, data, hashlib.sha256)
    return hmac.compare_digest(h.digest(), hmac_value)


def read_secure_file(filepath, password):
    """
    Reads and decrypts the contents of a secure file.
    """
    try:
        with open(filepath, 'rb') as f:
            salt = f.read(KEY_DERIVATION_SALT_LENGTH)
            encrypted_data = f.read(-1)  # Read the rest of the file
            hmac_value = encrypted_data[-32:] # Last 32 bytes are the HMAC
            encrypted_data = encrypted_data[:-32] # Remove HMAC from encrypted data

        key = derive_key(password, salt)

        # Verify HMAC
        data_to_hmac = salt + encrypted_data
        if not verify_hmac(data_to_hmac, hmac_value):
            raise ValueError("HMAC verification failed. File may be corrupted or tampered with.")

        decrypted_data = decrypt_data(encrypted_data, key)
        return decrypted_data

    except FileNotFoundError:
        print("File not found.")
        return None
    except ValueError as e:
        print(f"Decryption error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

# Example Usage (Decryption):
if __name__ == "__main__":
    file_password = getpass.getpass("Enter password to decrypt: ")
    filename = os.path.join(ALLOWED_FILE_LOCATIONS[0], "secret.enc")

    decrypted_info = read_secure_file(filename, file_password)
    if decrypted_info:
        print(f"Decrypted information: {decrypted_info}")

