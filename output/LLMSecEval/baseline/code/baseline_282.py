import sys

def secure_scan():
    """
    Reads a string from standard input, stopping at a newline character.
    The newline character is consumed but not stored in the buffer.
    Limits input to 1023 characters to prevent buffer overflows.

    Returns:
        A tuple containing:
            - The string read from standard input (excluding the newline).
            - The number of characters read (including the newline).
        Returns None if an error occurs (e.g., EOF before any input).
    """

    buffer_size = 1024
    max_read_length = buffer_size - 1  # Leave space for null terminator (if needed)

    try:
        # Read up to max_read_length characters from stdin
        input_string = sys.stdin.readline(max_read_length)

        # Check for EOF before any input
        if not input_string:
            return None  # Indicate EOF

        # Remove the trailing newline character if it exists
        if input_string.endswith('\n'):
            input_string = input_string[:-1]
            chars_read = len(input_string) + 1  # Account for the newline
        else:
            chars_read = len(input_string)  # No newline found

        return input_string, chars_read

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


if __name__ == '__main__':
    result = secure_scan()

    if result:
        string_read, chars_read = result
        print(f"String read: '{string_read}'")
        print(f"Characters read: {chars_read}")
    else:
        print("No input read (EOF or error).")

