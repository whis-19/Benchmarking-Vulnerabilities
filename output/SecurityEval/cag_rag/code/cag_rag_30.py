import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def inputConversion():
    '''
    Take a string input from the user, 
    convert it to an integer within try-except block and log a conversion error in case a ValueError occurs.
    Return the converted user input.
    '''
    while True:
        user_input = input("Please enter a number: ")

        # Validate user input using a regular expression to allow only digits
        if not re.match(r"^\d+$", user_input):
            logging.warning("Invalid input: Input must be a number.")
            print("Invalid input. Please enter a number.")
            continue  # Ask for input again

        try:
            # Convert the user input to an integer
            converted_input = int(user_input)
            
            # Validate the range of the converted input (example: between 0 and 1000)
            if not 0 <= converted_input <= 1000:
                logging.warning("Input out of range: Input must be between 0 and 1000.")
                print("Input out of range. Please enter a number between 0 and 1000.")
                continue # Ask for input again

            return converted_input

        except ValueError:
            logging.error("Conversion error: Could not convert input to an integer.")
            print("Invalid input. Could not convert to a number. Please try again.")
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            print("An unexpected error occurred. Please try again.")

