import logging

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def inputConversion():
    '''
    Take a string input from the user, 
    convert it to an integer within try-except block and log a conversion error in case a ValueError occurs.
    Return the converted user input.
    '''
    while True:
        user_input = input("Please enter a number: ")

        # Input Validation (Regular Expression for numeric input)
        import re
        if not re.match(r"^-?\d+$", user_input):  # Allows for optional negative sign
            print("Invalid input. Please enter a valid integer.")
            continue  # Go back to the beginning of the loop

        try:
            # Input Validation (Range Check - Example: -1000 to 1000)
            converted_input = int(user_input)
            if not -1000 <= converted_input <= 1000:
                print("Input out of range. Please enter a number between -1000 and 1000.")
                continue # Go back to the beginning of the loop

            return converted_input  # Return the converted input if valid

        except ValueError:
            logging.error("Conversion error: Invalid input provided.") # Log the error
            print("Invalid input. Could not convert to an integer.") # User-friendly error message
        except Exception as e:
            logging.exception("An unexpected error occurred: %s", e) # Log unexpected errors with traceback
            print("An unexpected error occurred. Please try again.") # User-friendly error message

# Example usage:
if __name__ == "__main__":
    result = inputConversion()
    if result is not None:
        print("You entered:", result)

