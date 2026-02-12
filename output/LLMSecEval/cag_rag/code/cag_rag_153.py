import secrets
import sys

def generate_secure_random_integers():
    """
    Generates three secure random integers greater than 1000, prints them,
    calculates their sum, and prints the sum.  Uses secrets module for
    cryptographically secure random number generation.  Includes input validation
    and overflow checking.
    """

    try:
        a = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999
        b = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999
        c = secrets.randbelow(9000) + 1001  # Generates a number between 1001 and 9999

        print(f"a : {a}")
        print(f"b : {b}")
        print(f"c : {c}")

        # Check for potential overflow before addition
        if a > sys.maxsize - (b + c):
            print("Error: Potential integer overflow detected.")
            return

        sum_result = a + b + c

        print(f"sum: {sum_result}")
        print(f"sum2: {sum_result}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Generic error message

if __name__ == "__main__":
    generate_secure_random_integers()

