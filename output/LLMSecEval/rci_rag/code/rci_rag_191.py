# Instead of:
    # logging.info(f"User password: {password}")  # NEVER DO THIS!

    # Do this:
    logging.info("User submitted a password (length: %d)", len(password))

