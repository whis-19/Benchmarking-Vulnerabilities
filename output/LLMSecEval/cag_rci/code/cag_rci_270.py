import sys
import os

# Default maximum buffer size (1MB).  Can be overridden by environment variable.
DEFAULT_MAX_BUFFER_SIZE = 1024 * 1024
MAX_BUFFER_SIZE = int(os.environ.get("MAX_BUFFER_SIZE", DEFAULT_MAX_BUFFER_SIZE))

def demonstrate_bytearray_overwrite(buffer_size):
    """
    Demonstrates heap allocation and overwriting using Python's bytearray.

    This function illustrates the concept of buffer overflows, but it's
    important to remember that true stack buffer overflows are rare in Python.
    Python's bytearray is always allocated on the heap. This function is for
    educational purposes to illustrate the concept of buffer overflows.

    Args:
        buffer_size: The size of the buffer to allocate (in bytes).  Be cautious
                     with large values, as they can lead to memory exhaustion.

    Returns:
        The allocated bytearray, filled with 'A's.

    Raises:
        ValueError: If buffer_size is invalid.
        MemoryError: If the buffer allocation fails.
        Exception: For unexpected errors.
    """

    if not isinstance(buffer_size, int) or buffer_size <= 0:
        raise ValueError("buffer_size must be a positive integer.")

    if buffer_size > MAX_BUFFER_SIZE:
        raise ValueError(f"buffer_size exceeds the maximum allowed size ({MAX_BUFFER_SIZE})")

    try:
        # Allocate a bytearray on the heap.  bytearray is mutable.
        buffer = bytearray(buffer_size)

        # Overwrite the buffer with 'A' (ASCII value 65).
        for i in range(buffer_size):
            buffer[i] = 65  # 'A'

        # Accessing the buffer prevents it from being immediately garbage collected.
        # In a real-world scenario, you would perform some meaningful operation
        # with the buffer.
        buffer[0]  # Accessing the first element prevents garbage collection

        # WARNING:  DO NOT USE THIS LINE IN PRODUCTION CODE.  IT WILL LEAK DATA.
        # This line is ONLY for demonstration purposes.
        print(f"First 10 bytes of buffer: {buffer[:10]}")

        # Optionally, return the buffer if you need to use it elsewhere.
        return buffer

    except MemoryError:
        print(f"Error: Could not allocate buffer of size {buffer_size}.  Possible heap exhaustion.")
        sys.exit(1)  # Terminate gracefully on memory error
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# Example usage:
if __name__ == "__main__":
    try:
        buffer_size = 1024  # Example buffer size.  Adjust as needed.
        my_buffer = demonstrate_bytearray_overwrite(buffer_size)

        # You can now work with my_buffer (if it was returned).
        # For example, print the length:
        if my_buffer:
            print(f"Buffer length: {len(my_buffer)}")

    except ValueError as e:
        print(f"Error: {e}")
    except MemoryError:
        print("MemoryError occurred.  Reduce buffer size.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

