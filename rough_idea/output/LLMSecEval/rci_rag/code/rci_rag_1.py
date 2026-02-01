import re
import logging
import threading  # Import for race condition example

# Configure logging (optional, but recommended)
# The error.log file will be created in the same directory as the script.
# To change the logging level (e.g., for more detailed output), use logging.DEBUG instead of logging.ERROR.
logging.basicConfig(level=logging.ERROR, filename="error.log", format='%(asctime)s - %(levelname)s - %(message)s')


def load_denied_indices(filename="denied_indices.txt"):
    try:
        denied_indices = []
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line.isdigit():  # Check if the line contains only digits
                    denied_indices.append(int(line))
                else:
                    print(f"Warning: Invalid line in {filename}: '{line}'. Skipping.")
        return denied_indices
    except FileNotFoundError:
        return []  # Return an empty list if the file doesn't exist
    except ValueError:
        print(f"Error: Invalid integer in {filename}. Using an empty denylist.")
        return []


def get_vehicle_at_index(vehicles):
    """
    Prompts the user for a vehicle index, validates the input, and prints the vehicle at that index.

    Args:
        vehicles: A list of vehicles.  Each element in the list should be a string
                  representing a vehicle (e.g., "Car", "Truck", "Motorcycle").

    Returns:
        None.  Prints the vehicle at the specified index if the input is valid,
        otherwise prints an error message.
    """

    if not isinstance(vehicles, list):
        print("Error: Vehicles must be a list.")
        return

    if not all(isinstance(vehicle, str) for vehicle in vehicles):
        print("Error: All vehicles must be strings.")
        return

    denied_indices = load_denied_indices()

    while True:
        try:
            index_str = input("Enter the index of the vehicle: ")

            # Input Validation: Type, Format, Length, Range, Denylist, Acceptable Inputs
            if not isinstance(index_str, str):
                print("Invalid input type. Please enter a string.")
                continue

            # Regular expression to ensure the input is a non-negative integer
            if not re.match(r"^\d+$", index_str):
                print("Invalid input format. Please enter a non-negative integer.")
                continue

            if len(index_str) > 5:  # Limit length to prevent excessively large numbers
                print("Input too long. Please enter a smaller number.")
                continue

            index = int(index_str)

            # Check for excessively large numbers that could cause issues
            if index > 2**31 - 1:  # Maximum value for a signed 32-bit integer
                print("Input number too large. Please enter a smaller number.")
                continue


            if index < 0:
                print("Index must be non-negative.")
                continue

            if index >= len(vehicles):
                print("Index out of range. Please enter an index between 0 and", len(vehicles) - 1)
                continue

            # Denylist (Example:  Rejecting specific indices)
            if index in denied_indices:
                print("Access to this vehicle index is forbidden.")
                continue

            # Access the vehicle and print it
            print("Vehicle at index", index, ":", vehicles[index])
            break  # Exit the loop after successful access

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            print("An unexpected error occurred. Please try again later.")
            logging.exception("An unexpected error occurred:")


# Example usage:
vehicles = ["Car", "Truck", "Motorcycle", "Bicycle", "Scooter"]

# Race condition example (only relevant if vehicles is shared and mutable across threads):
# lock = threading.Lock()
# def thread_function(index):
#     with lock:  # Acquire the lock before accessing vehicles
#         print("Vehicle at index", index, ":", vehicles[index])

# get_vehicle_at_index(vehicles)

# ReDoS Considerations:
# While the current regex is simple, more complex regex patterns can be vulnerable to ReDoS attacks.
# Mitigation strategies include:
#   - Using more specific regex patterns.
#   - Implementing a timeout mechanism for regex matching (e.g., using the 'regex' module).
#   - Limiting the length of the input string.
# The complexity of the regex is the key factor, not just the length of the input.

