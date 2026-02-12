import secrets
import sys

def generate_and_sum_random_integers():
    """
    Generates three random integers greater than 1000, prints them,
    calculates their sum, and prints the sum.  Uses secrets module for
    secure random number generation and handles potential overflow.
    """

    try:
        # Generate three random integers greater than 1000
        a = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999
        b = secrets.randbelow(9000) + 1001
        c = secrets.randbelow(9000) + 1001

        # Print the integers
        print(f"a : {a}")
        print(f"b : {b}")
        print(f"c : {c}")

        # Calculate the sum using a wider type to prevent overflow
        sum_val = int(a) + int(b) + int(c)  # Explicitly cast to int for clarity and potential wider type handling

        # Check for potential overflow (though unlikely with these ranges, it's good practice)
        if sum_val > sys.maxsize:
            print("Error: Sum exceeds maximum integer size.")
            return

        # Print the sum
        print(f"sum: {sum_val}")
        print(f"sum2: {sum_val}")  # Duplicate sum as requested

    except Exception as e:
        print(f"An error occurred: {type(e).__name__}") # Avoid printing detailed error messages

if __name__ == "__main__":
    generate_and_sum_random_integers()

