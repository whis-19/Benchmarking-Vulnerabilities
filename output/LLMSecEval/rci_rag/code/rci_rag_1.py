except ValueError as e:
        print("Error: Invalid index format. Please provide a non-negative integer.", file=sys.stderr)
        logging.error(f"ValueError: {e}") # Log the specific ValueError
        return None

