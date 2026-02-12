import sys
import os

def allocate_and_read_input(buffer_size=1024, max_read_length=100):
    """
    Allocates a buffer of specified size and reads up to max_read_length characters
    from standard input into the buffer.  Handles potential buffer overflows and
    ensures null termination.

    Args:
        buffer_size (int): The size of the buffer to allocate in bytes. Defaults to 1024.
        max_read_length (int): The maximum number of characters to read from stdin. Defaults to 100.

    Returns:
        bytes: A byte string containing the data read from stdin, null-terminated.
               Returns None if allocation fails or an error occurs during reading.
    """
    try:
        # Allocate the buffer
        buf = bytearray(buffer_size)  # Use bytearray for mutable byte storage

        # Read from stdin, limiting the number of characters read
        input_bytes = os.read(sys.stdin.fileno(), max_read_length)  # Use os.read for direct file descriptor access

        # Check if we read anything
        if not input_bytes:
            return b""  # Return empty bytes if nothing was read

        # Determine the actual length of the input
        read_length = len(input_bytes)

        # Copy the input into the buffer
        buf[:read_length] = input_bytes

        # Null-terminate the buffer to prevent potential issues with string handling
        buf[read_length] = 0  # Null termination

        return bytes(buf[:read_length + 1])  # Return as bytes, including null terminator

    except OSError as e:
        print(f"Error reading from stdin: {e}")
        return None
    except MemoryError:
        print("Memory allocation failed.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def main():
    """
    Demonstrates the usage of the allocate_and_read_input function.
    """

    # Allocate and read into the first buffer
    buf = allocate_and_read_input()

    if buf is not None:
        print("First buffer content:", buf)
    else:
        print("Failed to read into the first buffer.")

    # Allocate and read into the second buffer
    buf1 = allocate_and_read_input()

    if buf1 is not None:
        print("Second buffer content:", buf1)
    else:
        print("Failed to read into the second buffer.")


if __name__ == "__main__":
    main()

