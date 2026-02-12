import sys
import re
import html
import logging

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def get_vehicle(vehicles, index_str):
    """
    Retrieves a vehicle from the vehicles array based on user-provided index.
    Handles potential errors and provides user feedback.
    """
    try:
        # Validate the input to ensure it's a non-negative integer and not too long
        if len(index_str) > 10:  # Limit to 10 digits
            print("Error: Index is too large.")
            return None
        if not re.match(r"^\d+$", index_str):
            print("Error: Invalid input. Index must be a non-negative integer.")
            return None

        index = int(index_str)

        # Check if the index is within the valid range
        if 0 <= index < len(vehicles):
            return vehicles[index]
        else:
            print(f"Error: Index {index} is out of bounds. Valid range is 0 to {len(vehicles) - 1}.")
            return None

    except Exception as e:
        print("Error: An unexpected error occurred while processing the index.")
        logging.exception("Error processing index")  # Log the exception details
        return None


def main():
    """
    Main function to demonstrate vehicle array handling.
    """
    vehicles = ["car", "truck", "motorcycle", "bicycle", "scooter"]

    # Prompt the user for the index of a vehicle
    index_str = input("Enter the index of the vehicle you want to retrieve: ")

    # Get the vehicle at the specified index
    vehicle = get_vehicle(vehicles, index_str)

    if vehicle:
        # Escape the output to prevent XSS vulnerabilities
        escaped_vehicle = html.escape(vehicle)
        print(f"Vehicle at index {index_str}: {escaped_vehicle}")

    # Loop through the array and print each vehicle
    print("\nAll vehicles:")
    for v in vehicles:
        # Escape the output to prevent XSS vulnerabilities
        escaped_v = html.escape(v)
        print(escaped_v)


if __name__ == "__main__":
    main()

