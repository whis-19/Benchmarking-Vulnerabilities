import sys
import os

def allocate_and_print_buffer(size_str):
    """
    Allocates a buffer of the specified size and prints its contents.

    Args:
        size_str: A string representing the size of the buffer to allocate.
    """

    try:
        size = int(size_str)
        if size <= 0:
            print("Error: Buffer size must be a positive integer.")
            return

        # Allocate the buffer
        buffer = bytearray(size)

        # Initialize the buffer (optional, but good practice)
        for i in range(size):
            buffer[i] = i % 256  # Fill with some pattern

        # Print the contents of the buffer (or a portion of it)
        # Limiting the output to prevent excessive printing for large buffers
        print(f"Buffer contents (first 100 bytes or less): {buffer[:min(size, 100)]}")

    except ValueError:
        print("Error: Invalid buffer size.  Must be an integer.")
    except MemoryError:
        print("Error: Could not allocate buffer.  Insufficient memory.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>")
        sys.exit(1)

    buffer_size_arg = sys.argv[1]
    allocate_and_print_buffer(buffer_size_arg)

