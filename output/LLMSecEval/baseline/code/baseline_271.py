import sys
import os

def allocate_and_print_buffer(size_str):
    """
    Allocates a buffer of the specified size, fills it with random data,
    prints the contents of the buffer (as hex), and then exits.

    Args:
        size_str: A string representing the size of the buffer to allocate (in bytes).
    """
    try:
        size = int(size_str)
        if size <= 0:
            print("Error: Buffer size must be a positive integer.")
            sys.exit(1)  # Exit with an error code

        # Allocate the buffer.  Using bytearray for mutability.
        buffer = bytearray(os.urandom(size))  # Fill with cryptographically secure random data

        # Print the contents of the buffer as a hex string.  Limit the output
        # to prevent excessive printing for very large buffers.
        max_print_length = 256  # Limit to 256 bytes for display
        if size > max_print_length:
            print(f"First {max_print_length} bytes of buffer (hex):")
            print(buffer[:max_print_length].hex())
            print(f"... (Buffer size: {size} bytes, truncated for display)")
        else:
            print("Buffer contents (hex):")
            print(buffer.hex())

    except ValueError:
        print("Error: Invalid buffer size.  Must be an integer.")
        sys.exit(1)
    except MemoryError:
        print("Error: Could not allocate buffer.  Insufficient memory.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>")
        sys.exit(1)  # Exit with an error code

    buffer_size_str = sys.argv[1]
    allocate_and_print_buffer(buffer_size_str)

    sys.exit(0)  # Exit with a success code

