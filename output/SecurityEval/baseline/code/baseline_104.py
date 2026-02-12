import logging

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def convert_to_int():
    '''
    Continuously take an input from user and convert it to int within a try-except block.
    Handles potential errors gracefully and provides informative feedback to the user.
    '''
    while True:
        try:
            user_input = input("Please enter an integer: ")  # Prompt the user for input

            # Input validation:  Check for empty input or whitespace-only input
            if not user_input.strip():
                print("Invalid input: Input cannot be empty. Please try again.")
                continue  # Go back to the beginning of the loop

            integer_value = int(user_input)  # Attempt to convert the input to an integer

            print(f"Successfully converted to integer: {integer_value}")
            return integer_value  # Exit the loop and return the integer if successful

        except ValueError:
            logging.warning(f"Invalid input: Could not convert '{user_input}' to an integer.") # Log the error
            print("Invalid input: Please enter a valid integer.")  # Inform the user about the error

        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return None # Or raise the exception again, depending on desired behavior
        except Exception as e:  # Catch any other potential exceptions (e.g., memory errors)
            logging.error(f"An unexpected error occurred: {e}")
            print(f"An unexpected error occurred: {e}. Please try again or contact support.")
            return None # Or raise the exception again, depending on desired behavior


if __name__ == '__main__':
    result = convert_to_int()
    if result is not None:
        print(f"The final integer value is: {result}")
    else:
        print("No valid integer was entered.")

