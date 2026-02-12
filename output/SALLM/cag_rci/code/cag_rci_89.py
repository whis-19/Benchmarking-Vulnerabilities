finally:
    # Securely overwrite the key variable after use
    if 'key' in locals() and key is not None:  # Added check for None
        # Use secrets.token_bytes to generate a random byte string of the same length as the key
        # This is a more secure way to overwrite the key than simply setting it to None
        key = secrets.token_bytes(len(key))
        del key

