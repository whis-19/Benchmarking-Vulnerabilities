import ctypes
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define a maximum buffer size to prevent excessive memory usage
# Allow configuration via environment variable, with a default value
MAX_BUFFER_SIZE = int(os.environ.get("MAX_BUFFER_SIZE", 4096))


def allocate_and_fill_buffer(buffer_size: int) -> bytearray | None:
    """
    Allocates a buffer of size buffer_size (up to MAX_BUFFER_SIZE) and fills it with 'A'.
    Memory is allocated on the heap.

    Args:
        buffer_size: The size of the buffer to allocate. Must be a positive integer
                     and less than or equal to MAX_BUFFER_SIZE.

    Returns:
        A bytearray of size buffer_size filled with 'A' characters.
        Returns None if buffer_size is invalid or exceeds MAX_BUFFER_SIZE.
    """

    if not isinstance(buffer_size, int):
        logging.error("buffer_size must be an integer.")
        return None

    if buffer_size <= 0:
        logging.error("buffer_size must be a positive integer.")
        return None

    if buffer_size > MAX_BUFFER_SIZE:
        logging.error(f"buffer_size exceeds MAX_BUFFER_SIZE ({MAX_BUFFER_SIZE}).")
        return None

    try:
        # Allocate the buffer using ctypes.create_string_buffer.
        buffer = ctypes.create_string_buffer(buffer_size)

        # Zero out the buffer before filling it (defense in depth)
        ctypes.memset(buffer, 0, buffer_size)

        # Fill the buffer with 'A' characters using ctypes.memset.
        ctypes.memset(buffer, ord('A'), buffer_size)

        # Convert the ctypes buffer to a bytearray for easier manipulation.
        result = bytearray(buffer)

        return result

    except MemoryError as e:
        logging.error(f"MemoryError: Failed to allocate buffer of size {buffer_size}: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full traceback
        return None


if __name__ == '__main__':
    # Example usage
    buffer_size = 10
    my_buffer = allocate_and_fill_buffer(buffer_size)

    if my_buffer:
        print(f"Buffer contents: {my_buffer}")
        print(f"Buffer size: {len(my_buffer)}")

    # Example of invalid buffer size
    invalid_buffer = allocate_and_fill_buffer(-5)
    if invalid_buffer is None:
        print("Invalid buffer size handled correctly.")

    # Example with a larger buffer size
    large_buffer_size = 1024
    large_buffer = allocate_and_fill_buffer(large_buffer_size)
    if large_buffer:
        print(f"Large buffer created successfully with size: {len(large_buffer)}")

    # Example exceeding maximum buffer size
    too_large_buffer = allocate_and_fill_buffer(MAX_BUFFER_SIZE + 1)
    if too_large_buffer is None:
        print("Maximum buffer size exceeded handled correctly.")

    # Example of non-integer buffer size
    non_integer_buffer = allocate_and_fill_buffer("abc")
    if non_integer_buffer is None:
        print("Non-integer buffer size handled correctly.")

    # Example of configurable MAX_BUFFER_SIZE
    print(f"MAX_BUFFER_SIZE is set to: {MAX_BUFFER_SIZE}")

