if not isinstance(data, list):
       logging.warning("Invalid input: data must be a list.")
       print("Error: Input data must be a list.", file=sys.stderr)
       return None

