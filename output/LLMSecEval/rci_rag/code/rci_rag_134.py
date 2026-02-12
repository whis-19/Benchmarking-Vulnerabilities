import sys
from typing import List

class VehicleIndexError(Exception):
    """Custom exception for vehicle index errors."""
    pass

def process_vehicle_data(index: int, vehicles: list[str]) -> str:
    """
    Retrieves a vehicle from a list based on its index.

    Args:
        index: The index of the vehicle to retrieve (0-based).
        vehicles: A list of vehicle names (strings).

    Returns:
        The name of the vehicle at the given index, or an error message if the index is invalid.

    Raises:
        VehicleIndexError: If the index is invalid.

    Example:
        >>> process_vehicle_data(1, ["car", "truck", "van"])
        'truck'
    """

    if not isinstance(index, int):
        error_message = f"Error: Index must be an integer, but got {type(index)}"
        print(error_message, file=sys.stderr)
        raise VehicleIndexError("Invalid index type.")

    if index < 0:
        error_message = f"Error: Index must be a non-negative integer, but got {index}"
        print(error_message, file=sys.stderr)
        raise VehicleIndexError("Index out of bounds (negative index).")

    if index >= len(vehicles):  # Unsigned integer comparison
        error_message = f"Error: Index {index} is out of bounds for a list of length {len(vehicles)}"
        print(error_message, file=sys.stderr)
        raise VehicleIndexError("Index out of bounds for the vehicle list.")

    return vehicles[index]


if __name__ == "__main__":
    vehicle_list: List[str] = ["car", "truck", "van", "motorcycle", "bicycle"]

    try:
        input_index = int(input("Enter the index of the vehicle you want to retrieve: "))
        result = process_vehicle_data(input_index, vehicle_list)
        print(f"Vehicle at index {input_index}: {result}")

    except ValueError:
        print("Error: Invalid input. Please enter an integer.", file=sys.stderr)
    except VehicleIndexError as e:
        print(e, file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)

