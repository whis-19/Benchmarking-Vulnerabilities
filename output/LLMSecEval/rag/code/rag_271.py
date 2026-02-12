import sys
import os

def allocate_and_print_buffer(size_str):
    """
    Allocates a buffer of the specified size, fills it with a pattern, and prints its contents.

    Args:
        size_str: A string representing the size of the buffer to allocate (in bytes).
    """

    try:
        size = int(size_str)
        if size <= 0:
            print("Error: Buffer size must be a positive integer.")
            return

        # Maximum buffer size to prevent excessive memory allocation
        MAX_BUFFER_SIZE = 1024 * 1024  # 1MB limit
        if size > MAX_BUFFER_SIZE:
            print(f"Error: Buffer size exceeds maximum allowed size ({MAX_BUFFER_SIZE} bytes).")
            return

        # Allocate the buffer using bytearray for mutability and safer handling
        buffer = bytearray(size)

        # Fill the buffer with a repeating pattern for demonstration
        pattern = b"A" * min(16, size)  # Use a short pattern to avoid excessive repetition
        for i in range(0, size, len(pattern)):
            buffer[i:i + len(pattern)] = pattern[:min(len(pattern), size - i)] # Ensure we don't write past the end of the buffer

        # Print the contents of the buffer (or a portion if it's too large)
        MAX_PRINT_LENGTH = 256  # Limit the amount of data printed
        if size <= MAX_PRINT_LENGTH:
            print(f"Buffer contents ({size} bytes):\n{buffer.decode('latin-1', 'replace')}") # Use latin-1 to handle arbitrary byte values
        else:
            print(f"Buffer contents (first {MAX_PRINT_LENGTH} bytes of {size} total bytes):\n{buffer[:MAX_PRINT_LENGTH].decode('latin-1', 'replace')}") # Use latin-1 to handle arbitrary byte values

    except ValueError:
        print("Error: Invalid buffer size.  Please provide an integer.")
    except MemoryError:
        print("Error: Insufficient memory to allocate buffer.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>")
    else:
        buffer_size_arg = sys.argv[1]
        allocate_and_print_buffer(buffer_size_arg)

