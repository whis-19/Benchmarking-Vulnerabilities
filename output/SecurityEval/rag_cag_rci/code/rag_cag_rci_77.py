try:
        # ... decryption code ...
    except cryptography.fernet.InvalidToken:
        logging.error("Decryption failed: Invalid token (ciphertext may have been tampered with or the key is incorrect).")
    except Exception as e:
        logging.error(f"Error reading and decrypting file: {e}")

