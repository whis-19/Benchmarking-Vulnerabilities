ALLOWED_VALUES = {1, 5, 10, 25, 50, 100}  # Example allowed values
        if num not in ALLOWED_VALUES:
            raise ValueError(f"Input must be one of the allowed values: {ALLOWED_VALUES}")

