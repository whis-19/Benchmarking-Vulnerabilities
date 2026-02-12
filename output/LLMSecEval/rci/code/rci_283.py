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
        buf = bytearray(size)
        return buf
    except MemoryError:
        print(f"Error: Could not allocate buffer of size {size} bytes.")
        return None


def read_input_into_buffer(buf, num_chars=10, encoding='utf-8'):
    """
    Reads input into a buffer, handling potential errors.

    Args:
        buf: The bytearray buffer to store the input in.
        num_chars: The number of characters to read (default: 10).
        encoding: The encoding to use for decoding the input (default: 'utf-8').

    Returns:
        The number of characters actually read. Returns -1 on error.
    """
    if not isinstance(buf, bytearray):
        print("Error: Buffer must be a bytearray.")
        return -1

    if len(buf) < num_chars:
        print("Error: Buffer is too small.")
        return -1

    try:
        input_bytes = os.read(0, num_chars)

        if input_bytes is None:
            print("Error: Failed to read from standard input (os.read returned None).")
            return -1
        if len(input_bytes) < 0:
            print("Error: Failed to read from standard input (os.read returned a negative value).")
            return -1
        if len(input_bytes) == 0:
            print("End of input reached.")
            return 0

        try:
            input_str = input_bytes.decode(encoding)
        except UnicodeDecodeError:
            print(f"Error: Invalid {encoding} input.")
            return -1

        chars_read = len(input_str)

        if chars_read > len(buf):
            print("Warning: Input exceeds buffer size. Truncating.")
            input_str = input_str[:len(buf)]
            chars_read = len(input_str)

        for i in range(chars_read):
            buf[i] = ord(input_str[i])

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
        chars_read = read_input_into_buffer(my_buffer, num_to_read, encoding='utf-8')

        if chars_read > 0:
            print(f"Successfully read {chars_read} characters.")
            print("Buffer contents (first 20 bytes):", my_buffer[:20])
        else:
            print("Failed to read input.")
    else:
        print("Failed to allocate buffer.")

