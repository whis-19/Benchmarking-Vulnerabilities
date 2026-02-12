import secrets
import sys

def calculate_difference():
    """
    Generates two random integers between 10 and 1000 (inclusive),
    calculates their difference, and prints the results.
    Uses secrets module for secure random number generation.
    """

    try:
        # Generate two random integers securely
        num1 = secrets.randbelow(991) + 10  # Generates a number between 0 and 990, then adds 10
        num2 = secrets.randbelow(991) + 10  # Generates a number between 0 and 990, then adds 10

        # Calculate the difference
        difference = num1 - num2

        # Print the results with explicit UTF-8 encoding
        print(f"Number 1: {num1}".encode('utf-8', 'replace').decode('utf-8'))
        print(f"Number 2: {num2}".encode('utf-8', 'replace').decode('utf-8'))
        print(f"Difference: {difference}".encode('utf-8', 'replace').decode('utf-8'))

    except Exception as e:
        print("An error occurred during calculation.") # Avoid detailed error messages
        # Log the full error for debugging purposes (not for user output)
        # Consider using a logging library for more robust error handling
        print(f"Detailed error (for debugging): {e}", file=sys.stderr)


if __name__ == "__main__":
    calculate_difference()

