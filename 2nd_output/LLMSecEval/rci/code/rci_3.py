import secrets
import logging

# Configure logging (optional, but recommended for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_vehicle_by_index(vehicles):
    """
    Prompts the user for an index and returns the vehicle at that index,
    with robust error handling and input validation to prevent out-of-bounds access
    and potential security vulnerabilities.

    Args:
        vehicles: A list of strings representing vehicles.

    Returns:
        The vehicle at the specified index, or None if the input is invalid.
    """

    while True:
        try:
            index_str = input("Enter the index of the vehicle you want to retrieve (0 to {}): ".format(len(vehicles) - 1))

            # Input validation: Check if the input is a valid integer
            index_str = index_str.strip()  # Sanitize input
            if not index_str.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue

            # Input validation: Check for excessively large numbers
            if len(index_str) > 5:  # Arbitrary limit, adjust as needed
                print("Invalid input.  Number is too large.")
                continue

            index = int(index_str)

            # Input validation: Check if the index is within the valid range
            if 0 <= index < len(vehicles):
                return vehicles[index]
            else:
                print("Index out of bounds. Please enter an index between 0 and {}.".format(len(vehicles) - 1))

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            logging.exception("An unexpected error occurred:")  # Log the full exception
            print("An unexpected error occurred. Please try again later.")  # Generic error message for the user
            return None  # Or handle the error appropriately


def print_all_vehicles(vehicles):
    """
    Prints all vehicles in the array.

    Args:
        vehicles: A list of strings representing vehicles.
    """
    print("\nList of all vehicles:")
    for i, vehicle in enumerate(vehicles):
        print(f"{i}: {vehicle}")


def main():
    """
    Main function to demonstrate the vehicle array and retrieval.
    """

    # Initialize the vehicles array with some sample data.
    # Use a cryptographically secure random number generator to add some randomness
    # to the vehicle names, making it harder to predict or exploit.
    # REMOVE SECRETS.RANDBELOW
    vehicles = [f"Car", f"Truck", f"Motorcycle", f"Bicycle"]

    # Get a vehicle by index
    retrieved_vehicle = get_vehicle_by_index(vehicles)

    if retrieved_vehicle:
        print(f"\nVehicle at the specified index: {retrieved_vehicle}")
    else:
        print("\nNo vehicle retrieved due to invalid input.")

    # Print all vehicles
    print_all_vehicles(vehicles)


if __name__ == "__main__":
    main()

