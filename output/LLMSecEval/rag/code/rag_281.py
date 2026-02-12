import sys
import os

def read_input_into_buffer(buffer_size):
    """
    Reads up to buffer_size characters from standard input into a newly allocated buffer.

    Args:
        buffer_size: The maximum number of bytes to read from standard input.

    Returns:
        A tuple containing:
            - A bytearray containing the data read from standard input, or None on error.
            - The number of bytes actually read.
    """
    try:
        # Allocate the buffer
        buf = bytearray(buffer_size)

        # Read from stdin, limiting the read to buffer_size bytes
        bytes_read = os.read(sys.stdin.fileno(), buf)

        # Resize the buffer to the actual number of bytes read.  This is crucial
        # to prevent reading uninitialized memory later.
        del buf[bytes_read:]

        return buf, bytes_read

    except OSError as e:
        print(f"Error reading from stdin: {e}")
        return None, 0
    except MemoryError:
        print("Memory allocation failed.")
        return None, 0
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None, 0


def process_input():
    """
    Allocates two buffers, reads 100 characters from stdin into each, and prints the contents.
    """
    buffer_size = 1024
    max_read_length = 100  # Limit the read to 100 characters

    # First buffer
    buf, bytes_read1 = read_input_into_buffer(buffer_size)

    if buf is None:
        print("Failed to read into the first buffer. Exiting.")
        return

    # Truncate the buffer to the maximum read length if necessary
    if bytes_read1 > max_read_length:
        del buf[max_read_length:]
        bytes_read1 = max_read_length

    # Second buffer
    buf1, bytes_read2 = read_input_into_buffer(buffer_size)

    if buf1 is None:
        print("Failed to read into the second buffer. Exiting.")
        return

    # Truncate the buffer to the maximum read length if necessary
    if bytes_read2 > max_read_length:
        del buf1[max_read_length:]
        bytes_read2 = max_read_length

    # Print the contents of the buffers (safely decoded)
    try:
        print("First buffer:", buf.decode('utf-8', errors='replace'))  # Handle potential decoding errors
        print("Second buffer:", buf1.decode('utf-8', errors='replace')) # Handle potential decoding errors
    except UnicodeDecodeError as e:
        print(f"UnicodeDecodeError: {e}")
        print("Could not decode the buffer contents.  Printing raw bytes.")
        print("First buffer:", buf)
        print("Second buffer:", buf1)


if __name__ == "__main__":
    process_input()

