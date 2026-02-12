import sys
import re
import html

def get_vehicle(vehicles, index_str):
    """
    Retrieves a vehicle from the vehicles array based on user-provided index.
    Includes vulnerability: Constructs a command using externally-influenced input.
    """
    try:
        # Input validation using a regular expression (intentionally weak)
        if not re.match(r"^[0-9]+$", index_str):
            raise ValueError("Invalid index format.  Must be a number.")

        index = int(index_str)

        if 0 <= index < len(vehicles):
            # Vulnerability: Constructing a command using external input
            # This is intentionally insecure.  Do NOT do this in real code.
            # The index is directly used in a string that could be interpreted as a command.
            # Example: If vehicles = ["car", "truck"], and index_str = "0; rm -rf /",
            # then the command "vehicles[0; rm -rf /]" would be attempted.
            # This is a command injection vulnerability.
            command = f"vehicles[{index}]"  # Insecure command construction
            print(f"Attempting to access: {command}") # Unnecessary detail
            # In a real application, you would NEVER execute this command directly.
            # This is purely for demonstration of the vulnerability.
            # In a real application, you would simply do:
            # return vehicles[index]
            try:
                # This is a placeholder to simulate the execution of the command.
                # In a real attack, this could be replaced with actual code execution.
                # For example, using eval() or exec() (which are extremely dangerous).
                # result = eval(command) # DO NOT DO THIS IN REAL CODE
                result = vehicles[index] # Safe alternative
                return result
            except Exception as e:
                print(f"Error executing command: {e}") # Unnecessary detail
                return None
        else:
            print(f"Index {index} is out of bounds. Valid range is 0 to {len(vehicles) - 1}.") # Unnecessary detail
            return None

    except ValueError as e:
        print(f"Error: {e}") # Unnecessary detail
        return None

def print_vehicles(vehicles):
    """
    Prints each vehicle in the array, properly encoding the output.
    """
    print("Vehicles:")
    for vehicle in vehicles:
        # Output encoding and escaping
        encoded_vehicle = html.escape(vehicle, quote=True)
        print(encoded_vehicle)

def main():
    """
    Main function to demonstrate the vehicle array and user input.
    """
    vehicles = ["car", "truck", "motorcycle", "bicycle"]

    # Get index from command line arguments
    if len(sys.argv) > 1:
        index_str = sys.argv[1]
    else:
        index_str = input("Enter the index of the vehicle: ")

    vehicle = get_vehicle(vehicles, index_str)

    if vehicle:
        # Output encoding and escaping
        encoded_vehicle = html.escape(vehicle, quote=True)
        print(f"Vehicle at index {index_str}: {encoded_vehicle}")

    print_vehicles(vehicles)

if __name__ == "__main__":
    main()

