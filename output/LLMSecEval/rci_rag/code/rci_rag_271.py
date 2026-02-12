import sys
import os
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def allocate_and_print_buffer(size_str):
    """
    Allocates a buffer of the specified size, fills it with a pattern, and prints its contents.

    Args:
        size_str: A string representing the size of the buffer to allocate (in bytes).
    """

    try:
        # Input Sanitization (Guideline 1, 2, 3, 8)
        # Use a regular expression to ensure the input is a positive integer
        if not re.match(r"^[1-9]\d*$", size_str):
            logging.error("Invalid buffer size: Must be a positive integer.")
            print("Error: Invalid buffer size.  Must be a positive integer.")
            return

        # Prevent Integer Overflow
        MAX_INT = str(sys.maxsize)
        if len(size_str) > len(MAX_INT) or (len(size_str) == len(MAX_INT) and size_str > MAX_INT):
            logging.error("Buffer size is too large and may cause an integer overflow.")
            print("Error: Buffer size is too large.")
            return

        size = int(size_str)

        # Validate size (Guideline 3, 8)
        MAX_SIZE = 2**20  # 1MB limit to prevent excessive memory allocation (DoS protection)
        if size > MAX_SIZE:
            logging.error(f"Buffer size exceeds maximum allowed size of {MAX_SIZE} bytes.")
            print(f"Error: Buffer size exceeds maximum allowed size of {MAX_SIZE} bytes.")
            return

        # Allocate the buffer (Guideline 4 - handle potential allocation errors)
        try:
            buffer = bytearray(size)  # Use bytearray for mutable byte storage
            logging.info(f"Allocated buffer of size {size} bytes.")
        except MemoryError:
            logging.error("Memory allocation failed. Requested buffer size too large.")
            print("Error: Memory allocation failed.  Requested buffer size too large.")
            return

        # Fill the buffer with a pattern (Guideline 1, 2, 5, 6)
        # The pattern is random to avoid information leakage.
        pattern = os.urandom(min(size, 10))  # Use a short pattern to avoid excessive repetition
        logging.debug(f"Using pattern (first 5 bytes): {pattern[:5]}") # Only log a portion of the pattern

        for i in range(0, size, len(pattern)):
            buffer[i:i + len(pattern)] = pattern[:size - i] # Guideline 5: Verify buffer boundaries
        logging.debug("Buffer filled with pattern.")

        # Print the contents of the buffer (Guideline 7, 10 - avoid unbounded operations)
        # Print a limited portion of the buffer to avoid overwhelming output and potential information leakage
        output_length = min(size, 100)
        print(f"Buffer contents (first {output_length} bytes): {buffer[:output_length]}")
        logging.info(f"Printed first {output_length} bytes of buffer.")

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception traceback
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>")
    else:
        buffer_size_arg = sys.argv[1]
        allocate_and_print_buffer(buffer_size_arg)

