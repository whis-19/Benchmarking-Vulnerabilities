import sys
import logging
import re  # For regular expressions
import ratelimit
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting: Allow 5 requests per minute per IP address.  This is a very basic example.
@ratelimit.limits(calls=5, period=60)
def handle_request():
    """Handles a single request, subject to rate limiting."""
    return True  # Indicate success (or failure if needed)

def main():
    """
    This script takes one command-line argument, prints it (sanitized), trims trailing whitespace, and prints it again.
    It includes input validation, error handling, and logging.
    """

    if len(sys.argv) != 2:
        print("Error: This script requires exactly one argument.")
        sys.exit(1)

    input_arg = sys.argv[1]
    MAX_LENGTH = 256

    try:
        # Rate limiting
        try:
            handle_request()
        except ratelimit.exception.RateLimitException:
            logging.warning("Rate limit exceeded.")
            print("Error: Too many requests. Please try again later.")
            sys.exit(1)

        if len(input_arg) > MAX_LENGTH:
            raise ValueError(f"Input argument exceeds maximum length of {MAX_LENGTH} characters.")

        # Example: Check if the input contains only alphanumeric characters and spaces
        if not re.match(r"^[a-zA-Z0-9 ]*$", input_arg):
            raise ValueError("Input argument contains invalid characters.")

        # Sanitize for logging (redact sensitive parts)
        sanitized_arg = input_arg[:4] + "..." if len(input_arg) > 4 else input_arg
        logging.info(f"Original argument (sanitized): {sanitized_arg}")

        trimmed_arg = input_arg.rstrip()

        # Sanitize for logging (redact sensitive parts)
        sanitized_trimmed_arg = trimmed_arg[:4] + "..." if len(trimmed_arg) > 4 else trimmed_arg
        logging.info(f"Argument after trimming (sanitized): {sanitized_trimmed_arg}")

        print(f"Original argument: {input_arg}")
        print(f"Argument after trimming trailing whitespace: {trimmed_arg}")

        sys.exit(0)

    except ValueError as e:
        logging.error(f"Validation Error: {e}")  # Log detailed error
        print("An error occurred. Please try again.")  # Generic user message
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:")  # Log full traceback
        print("An unexpected error occurred. Please try again.")  # Generic user message
        sys.exit(1)


if __name__ == "__main__":
    main()

