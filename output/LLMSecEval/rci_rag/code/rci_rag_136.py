import sys
import re
import html
import logging

logging.basicConfig(level=logging.INFO)  # Consider INFO or DEBUG for development

def get_vehicle(vehicles, index_str):
    """
    Retrieves a vehicle from the vehicles array based on user-provided index.

    Args:
        vehicles: A list of strings representing vehicles.
        index_str: A string representing the index of the desired vehicle.

    Returns:
        The vehicle at the specified index, or None if the index is invalid.
    """

    try:
        # Validate the input to ensure it's an integer
        if not re.match(r"^\d+$", index_str):
            print("Error: Invalid index format.  Please enter a non-negative integer.")
            return None

        index = int(index_str)
        assert 0 <= index < len(vehicles), "Index out of bounds" # Defense in depth

        return vehicles[index]


    except ValueError as e:
        logging.error(f"ValueError: Could not convert index to integer. Details: {e}")
        print("Error: Invalid input.")
        return None
    except AssertionError as e:
        logging.error(f"AssertionError: Index out of bounds: {e}")
        print("Error: Invalid index.")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred:")
        print("Error: An unexpected error occurred.")
        return None


def main():
    """
    Main function to demonstrate vehicle array processing.
    """

    vehicles = ["Car", "Truck", "Motorcycle", "Bicycle", "Scooter"]

    if len(sys.argv) != 2:
        print("Usage: python vehicles.py <index>")
        return

    index_str = sys.argv[1]

    # Get the vehicle at the specified index
    vehicle = get_vehicle(vehicles, index_str)

    if vehicle:
        # Escape the output before printing to prevent XSS
        escaped_vehicle = html.escape(vehicle)
        print(f"The vehicle at that index is: {escaped_vehicle}")

    # Loop through the array and print out each vehicle
    print("\nList of vehicles:")
    for v in vehicles:
        # Specify the output encoding (robustness against unexpected encoding issues)
        print(v.encode('utf-8', 'ignore').decode('utf-8')) # Handles potential encoding issues


if __name__ == "__main__":
    main()

