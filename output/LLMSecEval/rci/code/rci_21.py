import secrets
import time
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def generate_secure_numbers():
    """Generates two cryptographically secure random integers between 10 and 1000 (inclusive) and calculates their difference."""
    try:
        # Generate a cryptographically secure random integer between 10 and 1000 (inclusive).
        num1 = secrets.randbelow(991) + 10

        # Generate another cryptographically secure random integer between 10 and 1000 (inclusive).
        num2 = secrets.randbelow(991) + 10

        # Calculate the difference between the two integers.
        start_time = time.perf_counter()  # Start timing (for demonstration of potential timing attacks)
        difference = num1 - num2
        end_time = time.perf_counter()  # End timing

        # Print the results.  Consider using f-strings for clarity and security.
        print(f"First number: {num1}")
        print(f"Second number: {num2}")
        print(f"Difference: {difference}")
        print(f"Calculation time: {end_time - start_time:.6f} seconds") # Show timing

        # Note:  In a real-world scenario, printing the numbers could be an information leak.
        #       Also, timing variations (even small ones) could potentially be exploited in a more complex system.
        #       Consider side-channel attacks (e.g., power analysis, electromagnetic radiation) in high-security contexts.

    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)  # Log the exception with traceback
        print(f"An error occurred. See logs for details.")


if __name__ == "__main__":
    generate_secure_numbers()

