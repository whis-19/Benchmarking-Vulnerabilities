import logging

# Configure logging (as above)
logging.basicConfig(filename='conversion_errors.log', level=logging.ERROR, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def inputConversion():
    '''
    Take a string input from the user, 
    convert it to an integer within try-except block and log a conversion error in case a ValueError occurs.
    Return the converted user input.
    '''
    while True:  # Loop until valid input is received
        try:
            user_input = input("Please enter an integer: ")
            converted_input = int(user_input)
            return converted_input  # Exit the loop if conversion is successful
        except ValueError:
            logging.error(f"Invalid input: '{user_input}'. Could not convert to integer.")
            print("Invalid input. Please enter a valid integer.")  # Inform the user
        except Exception as e:  # Catch any other potential errors
            logging.exception(f"An unexpected error occurred: {e}") # Log the full exception
            print("An unexpected error occurred. Please try again.") # Inform the user

# Example usage:
result = inputConversion()
print(f"The converted integer is: {result}")

