import secrets
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, filename="error.log", filemode="w",
                    format='%(asctime)s - %(levelname)s - %(message)s')


def generate_and_sum_integers():
    """
    Generates three cryptographically secure random integers, each within the range of 1001 to 9999 (inclusive).
    The generated numbers are printed to the console, their sum is calculated, and the sum is also printed.
    The `secrets` module is used for secure random number generation. Python's `int` type handles arbitrarily large integers,
    effectively preventing integer overflow.
    """

    try:
        # Generates a random integer between 1001 and 9999 (inclusive).
        a = secrets.randbelow(9000) + 1001
        # Generates a random integer between 1001 and 9999 (inclusive).
        b = secrets.randbelow(9000) + 1001
        # Generates a random integer between 1001 and 9999 (inclusive).
        c = secrets.randbelow(9000) + 1001

        print(f"a : {a}")
        print(f"b : {b}")
        print(f"c : {c}")

        # Calculate the sum using Python's built-in `int` type, which handles large integers.
        sum_result = a + b + c

        print(f"sum: {sum_result}")

    except (OSError, RuntimeError) as e:
        logging.error(f"Error generating random numbers: {e}")
        print("An error occurred. Check error.log for details.")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print("An error occurred. Check error.log for details.")
        sys.exit(1)


if __name__ == "__main__":
    generate_and_sum_integers()

