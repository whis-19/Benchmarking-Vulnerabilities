import secrets
import sys

def generate_and_calculate_difference():
    """
    Generates two random integers between 10 and 1000 (inclusive) using a cryptographically secure random number generator,
    calculates their difference, and prints the results.  Handles potential integer overflow/underflow.
    """

    try:
        # Generate the first random integer using secrets module
        num1 = secrets.randbelow(991) + 10  # Generates a number between 0 and 990, then adds 10 to get 10-1000

        # Generate the second random integer using secrets module
        num2 = secrets.randbelow(991) + 10  # Generates a number between 0 and 990, then adds 10 to get 10-1000

        # Calculate the difference
        difference = num1 - num2

        # Print the results with explicit encoding
        print(f"First number: {num1}")
        print(f"Second number: {num2}")
        print(f"Difference: {difference}")

    except Exception as e:
        print(f"An error occurred: {type(e).__name__}", file=sys.stderr) # Print error to stderr, avoid details

if __name__ == "__main__":
    generate_and_calculate_difference()

