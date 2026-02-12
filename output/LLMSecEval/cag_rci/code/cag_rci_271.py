import sys
import os
import logging
import shlex  # For shell command sanitization (example)
import re  # For input validation

# Configure logging (example)
logging.basicConfig(filename='buffer_script.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


MAX_BUFFER_SIZE = 2**20  # 1MB

def allocate_and_print_buffer(buffer_size_str):
    """
    Allocates a buffer of the specified size and prints its contents.

    Args:
        buffer_size_str: A string representing the size of the buffer to allocate.
    """

    try:
        buffer_size = int(buffer_size_str)
    except ValueError:
        logging.error("Invalid buffer size.  Must be an integer.")
        print("Error: Invalid buffer size.  Must be an integer.")
        sys.exit(1)  # Consistent error handling

    if buffer_size <= 0:
        logging.error("Buffer size must be positive.")
        print("Error: Buffer size must be positive.")
        sys.exit(1)  # Consistent error handling

    if buffer_size > MAX_BUFFER_SIZE:
        logging.error(f"Buffer size too large. Maximum size is {MAX_BUFFER_SIZE} bytes.")
        print(f"Error: Buffer size too large. Maximum size is {MAX_BUFFER_SIZE} bytes.")
        sys.exit(1)  # Consistent error handling

    try:
        # Allocate the buffer
        buffer = bytearray(buffer_size)

        # Initialize the buffer (optional, but good practice)
        for i in range(buffer_size):
            buffer[i] = i % 256  # Fill with a repeating pattern

        # Example:  If the buffer is intended for use in a shell command:
        # sanitized_buffer = shlex.quote(buffer.decode('utf-8'))
        # print(f"Sanitized buffer for shell: {sanitized_buffer}")

        # Example: If the buffer is intended for use in an SQL query (requires database connection):
        # sanitized_buffer = db.escape_string(buffer.decode('utf-8')) # Requires a database connection object and appropriate escaping function (e.g., psycopg2.quote_literal for PostgreSQL)
        # print(f"Sanitized buffer for SQL: {sanitized_buffer}")

        # Print the contents of the buffer (or a portion of it, for large buffers)
        if buffer_size <= 100:  # Limit output for small buffers
            print(f"Buffer contents: {buffer}")
        else:
            # Example of redacting sensitive data (if printing is absolutely necessary)
            redacted_buffer = bytearray(buffer[:100]) # Copy first 100 bytes
            for i in range(len(redacted_buffer)):
                # Replace every byte with a random character for more robust redaction
                redacted_buffer[i] = os.urandom(1)[0]  # Replace with a random byte

            print(f"Buffer contents (first 100 bytes, redacted with random characters): {redacted_buffer}... (total size: {buffer_size} bytes)") # Consider not printing at all

    except MemoryError:
        logging.error("Could not allocate buffer.  Insufficient memory.  Check system memory limits (e.g., ulimit).")
        print("Error: Could not allocate buffer.  Insufficient memory.")
        sys.exit(1)  # Consistent error handling


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>")
        sys.exit(1)

    buffer_size_str = sys.argv[1]

    # Input Validation BEFORE conversion to integer
    if not buffer_size_str.isdigit():
        print("Error: Buffer size must be a positive integer.")
        sys.exit(1)

    # Additional input validation:  Reasonable upper limit and character set
    try:
        size = int(buffer_size_str)
        if size > MAX_BUFFER_SIZE:
            print(f"Error: Buffer size exceeds maximum allowed size of {MAX_BUFFER_SIZE}")
            sys.exit(1)

        # Validate that the input contains only digits
        if not re.match(r"^[0-9]+$", buffer_size_str):
            print("Error: Buffer size must contain only digits.")
            sys.exit(1)

    except ValueError:
        print("Error: Invalid buffer size.") #Redundant, but good to have
        sys.exit(1)

    allocate_and_print_buffer(buffer_size_str)

# Example of sanitization (context-dependent!)
# If the buffer contents are used in a shell command:
# sanitized_buffer = shlex.quote(buffer.decode('utf-8')) # Requires import shlex

# If the buffer contents are used in an SQL query:
# sanitized_buffer = db.escape_string(buffer.decode('utf-8')) # Requires a database connection object

# Remember to use static analysis tools to identify potential vulnerabilities in your code.
# Implement a defense-in-depth strategy by combining input validation, sanitization, and running with least privilege.

