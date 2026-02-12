def get_vehicle(vehicles):
        while True:
            try:
                index = input(f"Enter the index of the vehicle (0 to {len(vehicles) - 1}): ")

                if not index.isdigit():
                    print("Invalid input. Please enter a number.")
                    continue

                index = int(index)

                if 0 <= index < len(vehicles):
                    return vehicles[index]
                else:
                    print("Index out of range.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except IndexError:
                print("Index out of range.") # Handle index errors specifically
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
                import traceback
                traceback.print_exc()  # Log the traceback for debugging
                return None

