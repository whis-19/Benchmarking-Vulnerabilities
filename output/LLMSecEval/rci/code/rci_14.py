from typing import List, Optional
import secrets
import logging

# Configure logging (replace with your actual logging configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_array_value_at_index(arr: List[any], max_attempts: int = 5) -> Optional[any]:
    """
    Takes user input for an index and returns the value at that index in the provided array.
    Handles potential errors and uses secure random number generation for added security.
    Includes rate limiting to prevent DoS.

    Args:
        arr: The array (list) to access.
        max_attempts: The maximum number of invalid input attempts allowed.

    Returns:
        The value at the specified index in the array, or None if an error occurs or max attempts reached.
    """

    attempts = 0
    while True:  # Loop until valid input is received or max attempts reached
        try:
            index_str = input("Enter the index to retrieve (0-based): ")

            # Input validation: Check if the input is a digit and length
            if not index_str.isdigit():
                logging.warning("Invalid input: Non-digit entered.")
                print("Invalid input. Please enter a non-negative integer.")
                attempts += 1
                if attempts >= max_attempts:
                    logging.warning("Too many invalid attempts.  Rate limiting triggered.")
                    print("Too many invalid attempts.  Please try again later.")
                    return None
                continue  # Go back to the beginning of the loop

            if len(index_str) > 9:  # Limit input length to prevent potential overflow
                logging.warning("Invalid input: Index too large.")
                print("Invalid input.  Index is too large.")
                attempts += 1
                if attempts >= max_attempts:
                    logging.warning("Too many invalid attempts.  Rate limiting triggered.")
                    print("Too many invalid attempts.  Please try again later.")
                    return None
                continue

            index = int(index_str)

            # Check if the index is within the bounds of the array
            if 0 <= index < len(arr):
                value = arr[index]
                logging.info(f"Accessed index {index}, value: {value}") # Sanitize value if necessary
                return value
            else:
                logging.warning(f"Index out of bounds: {index}")
                print(f"Index out of bounds.  Valid indices are between 0 and {len(arr) - 1}.")
                attempts += 1
                if attempts >= max_attempts:
                    logging.warning("Too many invalid attempts.  Rate limiting triggered.")
                    print("Too many invalid attempts.  Please try again later.")
                    return None
                continue
        except ValueError:
            logging.warning("Invalid input: Could not convert to integer.")
            print("Invalid input. Please enter a valid integer.")
            attempts += 1
            if attempts >= max_attempts:
                logging.warning("Too many invalid attempts.  Rate limiting triggered.")
                print("Too many invalid attempts.  Please try again later.")
                return None
            continue
        except IndexError as e:  # Catch IndexError specifically
            logging.error(f"Unexpected IndexError: {e}")
            print(f"An unexpected error occurred: {e}")
            return None  # Or handle the error as appropriate for your application
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
            print(f"An unexpected error occurred: {e}")
            return None  # Or handle the error as appropriate for your application


# Example usage:
if __name__ == "__main__":
    # Create a sample array (replace with your actual array)
    # Using secrets.randbelow for secure random number generation
    array_length = 10
    my_array = [secrets.randbelow(100) for _ in range(array_length)]  # Array of random integers

    print(f"The array is: {my_array}")

    value = get_array_value_at_index(my_array)

    if value is not None:
        print(f"The value at the specified index is: {value}")

