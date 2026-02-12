import logging

    logging.basicConfig(level=logging.ERROR)  # Configure logging

    try:
        # ...
    except InvalidTag:
        logging.error("Decryption failed: Authentication failed (invalid tag).  Possible tampering!")
        print("Decryption failed: Authentication failed (invalid tag).  Possible tampering!") # Keep print for immediate feedback

