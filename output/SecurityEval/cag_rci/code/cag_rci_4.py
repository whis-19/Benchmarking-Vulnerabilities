except ValidationError as e:
        # For more detailed error information, log the full 'e' object
        raise ValueError(f"Invalid data: {e}")

