import logging
import logging.handlers  # Import for log rotation

def get_vehicle_at_index(vehicles):
    """
    Prompts the user for a vehicle index, validates it, and prints the vehicle at that index.

    Args:
        vehicles: A list of vehicle objects (e.g., strings, dictionaries, or custom objects).
    """

    while True:
        try:
            index_str = input("Enter the index of the vehicle you want to view: ")
            index_str = index_str.strip()  # Remove leading/trailing whitespace

            # Limit the input length to prevent DoS
            if len(index_str) > 10:  # Example: Limit to 10 digits (handles indices up to 9,999,999,999)
                print("Input too long. Please enter a smaller index.")
                continue

            # Input validation: Check if the input is a digit
            if not index_str.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue

            index = int(index_str)

            MAX_INDEX = 1000  # Example maximum index
            if index > MAX_INDEX:
                print("Index too large. Please enter a smaller index.")
                continue

            # Input validation: Check if the index is within the valid range
            if 0 <= index < len(vehicles):
                if not isinstance(vehicles[index], str):  # Assuming vehicles should be strings
                    logging.error(f"Unexpected data type at index {index}: {type(vehicles[index])}")
                    print("An unexpected error occurred. Please try again later.")
                    break

                print(f"Vehicle at index {index}: {vehicles[index]}")
                break  # Exit the loop after successful retrieval
            else:
                print(f"Index out of range. Please enter an index between 0 and {len(vehicles) - 1}.")

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except IndexError:
            print("Index out of range.  This should not happen if the input validation is correct.")
        except TypeError:  # Catch TypeError without exposing the specific error message
            logging.exception("Unexpected data type in vehicles list:")
            print("An unexpected error occurred. Please try again later.")
            break # Or handle the TypeError in a more appropriate way
        except Exception as e:
            logging.exception("An unexpected error occurred:")  # Log the full exception
            print("An unexpected error occurred. Please try again later.")  # Generic message to the user
            break # Exit the loop in case of unexpected errors.  Prevents infinite loops.


# Example usage:
if __name__ == "__main__":
    # Configure basic logging
    logging.basicConfig(level=logging.ERROR)

    # Configure log rotation
    handler = logging.handlers.RotatingFileHandler(
        'error.log',
        maxBytes=1024 * 1024,  # 1 MB
        backupCount=5,  # Keep 5 old log files
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)


    # Example vehicle list (replace with your actual vehicle data)
    vehicles = [
        "Toyota Camry",
        "Honda Civic",
        "Ford F-150",
        "Tesla Model 3",
        "Chevrolet Silverado"
    ]

    get_vehicle_at_index(vehicles)

