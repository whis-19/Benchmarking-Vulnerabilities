if len(index_str) > 10:  # Limit to 10 digits (adjust as needed)
        print("Error: Index too large.", file=sys.stderr)
        return None

    if index > 1000: # Or some other reasonable upper bound
        print("Error: Index too large.", file=sys.stderr)
        return None

