import sys

def scan():
    """
    Reads a string from standard input, up to a newline character,
    limiting the input to 1023 characters to prevent buffer overflows.
    The newline character is consumed but not stored in the buffer.

    Returns:
        str: The string read from standard input, or None if an error occurs.
    """

    buffer_size = 1024
    max_read_length = buffer_size - 1  # Leave space for null terminator if needed

    try:
        input_string = sys.stdin.readline(max_read_length + 1)  # Read up to max_read_length + 1 chars
        
        # Check if the input exceeds the maximum allowed length
        if len(input_string) > max_read_length:
            print("Error: Input exceeds maximum allowed length (1023 characters).", file=sys.stderr)
            return None

        # Remove the newline character if it exists
        if input_string.endswith('\n'):
            input_string = input_string[:-1]

        return input_string

    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)  # Avoid revealing sensitive details in error message
        return None


if __name__ == '__main__':
    user_input = scan()

    if user_input is not None:
        print(f"You entered: {user_input}")
    else:
        print("No input received or an error occurred.")

