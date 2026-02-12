import os

def allocate_buffer(size=1024):
    """
    Allocates a buffer of the specified size in bytes.

    Args:
        size: The size of the buffer to allocate (default: 1024).

    Returns:
        A bytearray representing the allocated buffer.  Returns None on error.
    """
    try:
        # Use bytearray for mutable buffer
        buf = bytearray(size)
        return buf
    except MemoryError:
        print(f"Error: Could not allocate buffer of size {size} bytes.")
        return None  # Handle memory allocation failure gracefully


def read_input_into_buffer(buf, num_chars=10):
    """
    Reads a specified number of characters from standard input and stores them in the provided buffer.

    Args:
        buf: The bytearray buffer to store the input in.
        num_chars: The number of characters to read (default: 10).

    Returns:
        The number of characters actually read. Returns -1 on error.
    """
    if not isinstance(buf, bytearray):
        print("Error: Buffer must be a bytearray.")
        return -1

    if len(buf) < num_chars:
        print("Error: Buffer is too small to hold the requested number of characters.")
        return -1

    try:
        # Read from standard input using os.read for lower-level control
        input_bytes = os.read(0, num_chars)  # 0 is the file descriptor for stdin

        # Decode the bytes to a string, handling potential decoding errors
        try:
            input_str = input_bytes.decode('utf-8')  # Or use a different encoding if needed
        except UnicodeDecodeError:
            print("Error: Invalid UTF-8 input.  Consider using a different encoding.")
            return -1

        # Get the actual number of characters read
        chars_read = len(input_str)

        # Copy the input string into the buffer
        for i in range(chars_read):
            buf[i] = ord(input_str[i])  # Store each character as its ASCII/Unicode value

        return chars_read

    except OSError as e:
        print(f"Error reading from standard input: {e}")
        return -1


if __name__ == "__main__":
    buffer_size = 1024
    my_buffer = allocate_buffer(buffer_size)

    if my_buffer:
        num_to_read = 10
        print(f"Enter {num_to_read} characters:")
        chars_read = read_input_into_buffer(my_buffer, num_to_read)

        if chars_read > 0:
            print(f"Successfully read {chars_read} characters.")
            print("Buffer contents (first 20 bytes):", my_buffer[:20])  # Print a portion of the buffer
        else:
            print("Failed to read input.")
    else:
        print("Failed to allocate buffer.")

