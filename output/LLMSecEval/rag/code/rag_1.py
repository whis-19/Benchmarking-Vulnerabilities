import re

def get_vehicle_at_index(vehicles):
    """
    Prompts the user for a vehicle index, validates the input, and prints the vehicle at that index.

    Args:
        vehicles: A list of vehicles.  Each element in the list should be a string
                  representing a vehicle (e.g., "Toyota Camry", "Ford F-150").

    Returns:
        None. Prints the vehicle at the specified index if the input is valid,
        otherwise prints an error message.
    """

    if not isinstance(vehicles, list):
        print("Error: Vehicles must be a list.")
        return

    if not all(isinstance(vehicle, str) for vehicle in vehicles):
        print("Error: All vehicles must be strings.")
        return

    while True:
        try:
            index_str = input("Enter the index of the vehicle: ")

            # Input Validation: Type, Format, Length, Denylist, Range
            if not isinstance(index_str, str):
                print("Invalid input type. Please enter a string.")
                continue

            # Regular expression to ensure the input is a non-negative integer
            if not re.match(r"^\d+$", index_str):
                print("Invalid input format. Please enter a non-negative integer.")
                continue

            if len(index_str) > 5:  # Limit the length to prevent excessively large numbers
                print("Input too long. Please enter a smaller number.")
                continue

            # Denylist (optional, but good practice for potentially problematic values)
            denied_inputs = ["666", "13"]  # Example:  Avoid potentially sensitive numbers
            if index_str in denied_inputs:
                print("Input is not allowed.")
                continue

            index = int(index_str)

            # Range validation: Check if the index is within the bounds of the list
            if 0 <= index < len(vehicles):
                print(f"Vehicle at index {index}: {vehicles[index]}")
                return  # Exit the loop after successful retrieval
            else:
                print(f"Index out of range. Please enter an index between 0 and {len(vehicles) - 1}.")

        except ValueError:
            print("Invalid input. Please enter a valid integer.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return # Exit on unexpected errors to prevent infinite loops


# Example usage:
if __name__ == "__main__":
    my_vehicles = ["Toyota Camry", "Ford F-150", "Honda Civic", "Tesla Model 3"]
    get_vehicle_at_index(my_vehicles)

