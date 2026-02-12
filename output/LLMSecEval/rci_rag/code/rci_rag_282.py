import sys
import logging

def scan():
    """
    Reads a string from standard input, up to a newline character,
    limiting the input to 1023 characters to prevent buffer overflows.
    The newline character is consumed but not stored in the buffer.

    Returns:
        str: The string read from standard input, or None if an error occurred.
    """

    buffer_size = 1024
    buffer = [None] * buffer_size  # Initialize a list to hold characters
    bytes_read = 0

    try:
        for i in range(buffer_size - 1):  # Leave space for null terminator
            char = sys.stdin.buffer.read(1).decode('utf-8')  # Read one byte and decode as UTF-8

            if not char:  # Check for EOF
                break

            if char == '\n':
                break  # Stop reading at newline

            buffer[i] = char
            bytes_read += 1

        # Null-terminate the string
        buffer[bytes_read] = '\0'

        # Convert the list of characters to a string
        result = "".join(buffer[:bytes_read])

        return result

    except Exception as e:
        logging.exception("Error reading input:")  # Logs the full exception
        print("Error reading input.", file=sys.stderr)  # Generic error message
        return None


if __name__ == '__main__':
    logging.basicConfig(filename='error.log', level=logging.ERROR)
    user_input = scan()

    if user_input is not None:
        print(f"You entered: {user_input}")
    else:
        print("No input received or an error occurred.")

