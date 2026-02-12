import sys
import re

def get_vehicle_at_index(vehicles, index_str):
    """
    Retrieves a vehicle from a list based on a user-provided index, with robust error handling and input validation.

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
            print(f"Error: Index {index} is out of bounds. Valid indices are 0 to {len(vehicles) - 1}.", file=sys.stderr)
            return None

        return vehicles[index]

    except ValueError as e:  # Catch potential errors during integer conversion (though regex should prevent this)
        print(f"Error: Could not convert index to integer: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return None


if __name__ == "__main__":
    # Example usage:  Take vehicle list and index as command-line arguments.
    if len(sys.argv) < 3:
        print("Usage: python script.py <vehicle1> <vehicle2> ... <index>", file=sys.stderr)
        sys.exit(1)

    vehicles = sys.argv[1:-1]  # All arguments except the last one are vehicles
    index_str = sys.argv[-1]   # The last argument is the index

    vehicle = get_vehicle_at_index(vehicles, index_str)

    if vehicle:
        print(f"Vehicle at index {index_str}: {vehicle}")
    else:
        # Error message already printed by get_vehicle_at_index
        pass

