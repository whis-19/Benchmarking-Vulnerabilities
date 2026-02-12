import re
import logging
import time
import os
import functools
import threading

# Configure logging (consider a more robust setup for production using logging.yaml)
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limit from environment variable
max_requests_per_second = int(os.environ.get("MAX_REQUESTS_PER_SECOND", 10))  # Default to 10

def rate_limit(max_calls_per_second):
    """Decorator to limit the rate of function calls."""
    last_called = 0.0
    calls_this_second = 0
    lock = threading.Lock()

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal last_called, calls_this_second
            with lock:
                now = time.time()
                if now - last_called >= 1.0:
                    calls_this_second = 0
                    last_called = now
                if calls_this_second < max_calls_per_second:
                    calls_this_second += 1
                    return func(*args, **kwargs)
                else:
                    print("Rate limit exceeded (decorator).")
                    logging.warning("Rate limit exceeded (decorator).")
                    time.sleep(1)  # Wait before retrying
                    return None  # Or raise an exception
        return wrapper
    return decorator

@rate_limit(max_requests_per_second)
def convert_to_int():
    '''
    Continuously take an input from user and convert it to int within a try-except block.
    Includes input validation and error handling for security.
    '''
    while True:
        user_input = input("Enter an integer (or 'q' to quit): ")

        if user_input.lower() == 'q':
            print("Exiting...")
            logging.info("Application exiting gracefully.")
            return None # Indicate exit to the caller

        # Input Validation using Regular Expression (Strict ASCII digits)
        if not re.match(r"^-?[0-9]+$", user_input):  # Allows optional negative sign and digits only (ASCII only)
            print("Invalid input. Please enter a valid integer using only ASCII digits.")
            logging.warning(f"Invalid input received: {user_input}. Input rejected due to invalid format.")
            continue

        try:
            # Convert to integer
            num = int(user_input)

            # Range Validation (Example: Restrict to a reasonable range)
            lower_bound = -1000000
            upper_bound = 1000000
            if not lower_bound < num < upper_bound:
                print(f"Input out of allowed range. Please enter an integer between {lower_bound:,} and {upper_bound:,}.") # Added comma formatting for readability
                logging.warning(f"Input {num} out of range.  Range is {lower_bound} to {upper_bound}.")
                continue

            print("You entered:", num)
            logging.info(f"Successfully processed input: {num}")
            return num  # Successfully converted and validated

        except ValueError:
            # This should not happen given the regex check, but included for robustness
            print("Invalid input. Could not convert to integer (ValueError).")
            logging.error("ValueError occurred despite regex validation.  This indicates a potential issue with the regex or integer conversion process.")
        except OverflowError:
            print("Integer overflow. The number is too large to represent.")
            logging.error("OverflowError occurred. Input was too large to represent as an integer.")
        except Exception as e:  # Catch any other unexpected errors
            print("An unexpected error occurred. Please try again.")
            logging.exception("An unexpected error occurred during input processing.") # Logs the full exception details (without printing to console)

        # Implement a simple delay to mitigate potential DoS (Rate Limiting)
        time.sleep(0.1)  # Add a small delay (e.g., 0.1 seconds)

if __name__ == '__main__':
    # Basic Rate Limiting Example (more sophisticated methods exist)
    start_time = time.time()
    request_count = 0

    while True:
        current_time = time.time()
        if current_time - start_time >= 1:  # Reset counter every second
            request_count = 0
            start_time = current_time

        if request_count < max_requests_per_second:
            result = convert_to_int()
            if result is not None:
                request_count += 1
                if result is None:
                    break # Exit if convert_to_int returned None (user quit)
        else:
            print("Rate limit exceeded. Please try again later.")
            logging.warning("Rate limit exceeded.  Requests are being throttled.")
            time.sleep(1)  # Wait before allowing more requests

