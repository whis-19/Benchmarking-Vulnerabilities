import sys
import re

def get_vehicle_at_index(vehicles, index_str):
    """
    Retrieves a vehicle from a list based on a user-provided index, with robust input validation and error handling.

    Args:
        vehicles: A list of vehicle objects (e.g., strings representing vehicle names).
        index_str: A string representing the index of the desired vehicle.

    Returns:
        The vehicle at the specified index, or None if the index is invalid.  Prints error messages to stderr.
    """

    if not isinstance(vehicles, list):
        print("Error: Vehicles must be a list.", file=sys.stderr)
        return None

    if not isinstance(index_str, str):
        print("Error: Index must be a string.", file=sys.stderr)
        return None

    # Validate the index string using a regular expression.  Must be a non-negative integer.
    if not re.match(r"^\d+$", index_str):
        print("Error: Invalid index format.  Please enter a non-negative integer.", file=sys.stderr)
        return None

    try:
        index = int(index_str)  # Convert to integer *after* validation

        # Check for out-of-bounds access.  Crucial security check.
        if index < 0 or index >= len(vehicles):
            print(f"Error: Index {index} is out of bounds. Valid range is 0 to {len(vehicles) - 1}.", file=sys.stderr)
            return None

        return vehicles[index]

    except ValueError as e:
        print(f"Error: Could not convert index to integer: {e}", file=sys.stderr) # More specific error message
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None


if __name__ == "__main__":
    # Example usage with command-line argument for the index.
    vehicles = ["Car", "Truck", "Motorcycle", "Bicycle"]

    if len(sys.argv) != 2:
        print("Usage: python script.py <vehicle_index>", file=sys.stderr)
        sys.exit(1)

    index_str = sys.argv[1]

    vehicle = get_vehicle_at_index(vehicles, index_str)

    if vehicle:
        print(f"Vehicle at index {index_str}: {vehicle}")
    else:
        # Error message already printed by get_vehicle_at_index
        pass

