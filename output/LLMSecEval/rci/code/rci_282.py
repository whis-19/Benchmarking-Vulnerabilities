import sys
import select
import logging

# Configure logging (optional, but recommended)
logging.basicConfig(filename='secure_scan.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def secure_scan(timeout=10, encoding='utf-8', max_input_length=1023):
    """
    Reads a string from standard input with timeout and encoding handling,
    using select.select() for timeout management.

    Args:
        timeout (int): Timeout in seconds for reading input.
        encoding (str): The encoding to use for decoding the input stream.
        max_input_length (int): Maximum number of bytes to read.

    Returns:
        str: The string read from standard input (excluding the newline),
             or None if an error occurred.
        int: The number of characters read (excluding the newline),
             or -1 if an error occurred.
    """

    buffer = bytearray()
    bytes_read = 0

    try:
        while True:
            rlist, _, _ = select.select([sys.stdin.buffer], [], [], timeout)
            if not rlist:
                raise TimeoutError("Input timed out")

            char = sys.stdin.buffer.read(1)

            if not char:  # EOF
                if not buffer:
                    return None, -1
                else:
                    try:
                        decoded_buffer = buffer.decode(encoding)
                        return decoded_buffer, len(decoded_buffer)
                    except UnicodeDecodeError as e:
                        logging.error(f"UnicodeDecodeError: {e}")
                        print("Error: Invalid encoding in input.")
                        return None, -1

            if char == b'\n':
                try:
                    decoded_buffer = buffer.decode(encoding)
                    return decoded_buffer, len(decoded_buffer)
                except UnicodeDecodeError as e:
                    logging.error(f"UnicodeDecodeError: {e}")
                    print("Error: Invalid encoding in input.")
                    return None, -1

            if bytes_read < max_input_length:
                buffer.extend(char)
                bytes_read += 1
            else:
                print("Warning: Input truncated to prevent buffer overflow.")
                try:
                    decoded_buffer = buffer.decode(encoding)
                    return decoded_buffer, len(decoded_buffer)
                except UnicodeDecodeError as e:
                    logging.error(f"UnicodeDecodeError: {e}")
                    print("Error: Invalid encoding in input.")
                    return None, -1

    except TimeoutError as e:
        logging.error(f"TimeoutError: {e}")
        print("Error: Input timed out.")
        return None, -1
    except OSError as e:
        logging.error(f"OSError: {e}")
        print("Error reading input (OSError).")
        return None, -1
    except ValueError as e:
        logging.error(f"ValueError: {e}")
        print("Error: Invalid input value.")
        return None, -1
    except Exception as e:
        logging.exception("Unexpected error during input processing.")  # Log full traceback
        print("Error: An unexpected error occurred. See log for details.")
        return None, -1


if __name__ == '__main__':
    input_string, num_chars = secure_scan(timeout=5, encoding='utf-8')

    if input_string is not None:
        print(f"Read string: '{input_string}'")
        print(f"Number of characters read: {num_chars}")
    else:
        print("No input read or an error occurred.")

