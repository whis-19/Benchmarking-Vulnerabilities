def string_to_int(s):
    """
    Safely converts a string to an integer.  Handles potential errors.
    """
    try:
        return int(s)
    except ValueError:
        raise ValueError("Invalid integer value: {}".format(s)) # Raise an exception

