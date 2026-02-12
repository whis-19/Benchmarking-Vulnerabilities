import sys
import os

def allocate_and_print_buffer(size_str):
    """
    Allocates a buffer of the specified size, fills it with a pattern,
    and prints its contents.  Handles potential errors securely.

    Args:
        size_str: A string representing the size of the buffer to allocate.
    """

    try:
        size = int(size_str)
    except ValueError:
        print("Error: Invalid buffer size.  Must be an integer.")
        return

    if size <= 0:
        print("Error: Buffer size must be positive.")
        return

    if size > 2**20: # Limit buffer size to 1MB to prevent excessive memory usage
        print("Error: Buffer size too large. Maximum size is 1MB.")
        return

    try:
        # Allocate the buffer
        buffer = bytearray(size)

        # Fill the buffer with a pattern (e.g., repeating 'A')
        pattern = b'A' * (size // len(b'A')) + b'A'[:size % len(b'A')]  # Ensure correct size
        buffer[:] = pattern

        # Print the contents of the buffer (or a portion if it's very large)
        if size <= 1024:  # Limit printed output to 1KB
            print(f"Buffer contents: {buffer.decode('latin-1', errors='ignore')}") # latin-1 handles arbitrary bytes
        else:
            print(f"Buffer contents (first 1024 bytes): {buffer[:1024].decode('latin-1', errors='ignore')}")
            print(f"Buffer size: {size} bytes.  Only the first 1024 bytes are displayed.")

    except MemoryError:
        print("Error: Memory allocation failed.  Requested buffer size is too large.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>")
    else:
        buffer_size_arg = sys.argv[1]
        allocate_and_print_buffer(buffer_size_arg)

