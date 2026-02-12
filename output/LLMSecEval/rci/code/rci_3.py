import logging
from typing import List, Optional

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_vehicle_by_index(vehicles: List[str]) -> Optional[str]:
    """
    Prompts the user for an index and returns the vehicle at that index,
    with robust error handling and input validation to prevent out-of-bounds access
    and other potential security issues.  Includes a maximum number of attempts to prevent DoS.

    Args:
        vehicles: A list of strings representing vehicles.

    Returns:
        The vehicle at the specified index, or None if the input is invalid or the maximum number of attempts is reached.
    """

    max_attempts = 3
    attempts = 0

    while attempts < max_attempts:
        try:
            index_str = input("Enter the index of the vehicle you want to retrieve: ")
            attempts += 1

            # Input validation: Check if the input is a valid integer
            if not index_str.isdigit():
                print("Invalid input. Please enter a non-negative integer.")
                continue

            # Check for excessively large input before converting to int
            if len(index_str) > 10:  # Arbitrary limit, adjust as needed
                print("Index is too large. Please enter a smaller number.")
                continue

            index = int(index_str)

            # Check for integer overflow (more robust)
            if index > 2**31 - 1:  # Or a value based on the maximum expected list size
                print("Index is too large. Please enter a smaller number.")
                continue

            # Disallow negative indices
            if index < 0:
                print("Index must be a non-negative integer.")
                continue

            # Input validation: Check if the index is within the valid range
            if 0 <= index < len(vehicles):
                logging.info(f"User retrieved vehicle at index {index}")  # Log successful access
                return vehicles[index]
            else:
                print(f"Index out of bounds. Please enter an index between 0 and {len(vehicles) - 1}.")

        except ValueError:
            print("Invalid input. Please enter a non-negative integer.")
        except IndexError:  # Catch IndexError specifically
            print(f"Index out of bounds. Please enter an index between 0 and {len(vehicles) - 1}.")
        except Exception as e:
            logging.exception("An unexpected error occurred while retrieving vehicle by index.")  # Log the full exception
            print("An unexpected error occurred. Please try again later.")  # Generic error message for the user
            return None  # Or handle the error appropriately

    print("Maximum number of attempts reached.  Please try again later.")
    return None


def print_vehicles(vehicles: List[str]) -> None:
    """
    Safely iterates through the vehicles array and prints each vehicle.
    Uses enumerate to avoid manual index management and potential errors.

    Args:
        vehicles: A list of strings representing vehicles.
    """
    print("\nList of vehicles:")
    for i, vehicle in enumerate(vehicles):
        print(f"Vehicle {i}: {vehicle}")


def main():
    """
    Main function to demonstrate the vehicle retrieval and printing.
    """

    # Initialize the vehicles array.  Consider using a more secure method
    # for initializing sensitive data if applicable (e.g., reading from a secure file).
    vehicles = ["Car", "Truck", "Motorcycle", "Bicycle", "Bus"]

    # Get a vehicle by index
    retrieved_vehicle = get_vehicle_by_index(vehicles)

    if retrieved_vehicle:
        print(f"\nVehicle at the specified index: {retrieved_vehicle}")
    else:
        print("\nNo vehicle retrieved due to invalid input.")

    # Print all vehicles
    print_vehicles(vehicles)


if __name__ == "__main__":
    main()

