import logging
import os  # For environment variables

# Configuration (ideally loaded from a config file or environment variables)
MAX_SIZE = int(os.environ.get("MAX_SIZE", 1024 * 1024))  # Default to 1MB
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Configure logging
logging.basicConfig(level=LOG_LEVEL)


def validate_size(size, max_size=MAX_SIZE):
    """
    Validates the size parameter, ensuring it's a positive integer within the allowed limit.

    Args:
        size: The size to validate (integer).
        max_size: The maximum allowed size (integer).  Defaults to MAX_SIZE.

    Returns:
        The validated size (integer) if valid.

    Raises:
        TypeError: If size is not an integer.
        ValueError: If size is not positive or exceeds max_size.
    """

    if not isinstance(size, int):
        logging.error(f"Invalid size type: {type(size)}")
        raise TypeError("Size must be an integer.")

    if size <= 0:
        logging.error(f"Invalid size value: {size}")
        raise ValueError("Size must be a positive integer.")

    if size > max_size:
        logging.error(f"Size exceeds maximum allowed size: {size} > {max_size}")
        raise ValueError(f"Size exceeds the maximum allowed size of {max_size} bytes.")

    return size  # Return the validated size


# Example Usage (demonstrating error handling)
if __name__ == "__main__":
    try:
        valid_size = validate_size(500000)
        print(f"Valid size: {valid_size}")

        invalid_size_type = validate_size("1000")  # String instead of int
        print(f"Invalid size type: {invalid_size_type}")  # This line won't be reached

    except TypeError as e:
        print(f"TypeError: {e}")
    except ValueError as e:
        print(f"ValueError: {e}")

    try:
        too_large_size = validate_size(2000000)  # Exceeds MAX_SIZE
        print(f"Too large size: {too_large_size}") # This line won't be reached
    except ValueError as e:
        print(f"ValueError: {e}")

    try:
        negative_size = validate_size(-100)
        print(f"Negative size: {negative_size}") # This line won't be reached
    except ValueError as e:
        print(f"ValueError: {e}")

