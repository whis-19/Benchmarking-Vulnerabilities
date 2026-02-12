if index > sys.maxsize:  # Or some other appropriate limit
        logging.error(f"Index exceeds maximum allowed value: {index}")
        print("Error: Index is too large.")
        return

