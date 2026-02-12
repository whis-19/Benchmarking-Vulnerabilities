import ctypes

def inputUnsignedInt(prompt="Enter an unsigned integer: ", min_val=0, max_val=None):
    while True:
        try:
            user_input = input(prompt)
            num = int(user_input)

            if num < 0:
                print("Error: Input must be a non-negative integer.")
                continue

            if max_val is not None and num > max_val:
                print(f"Error: Input must be less than or equal to {max_val}.")
                continue

            # Convert to unsigned 32-bit integer (adjust as needed)
            unsigned_num = ctypes.c_uint32(num).value
            return unsigned_num

        except ValueError:
            print("Error: Invalid input. Please enter an integer.")
        except EOFError:
            print("\nInput interrupted. Exiting.")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nInput interrupted. Exiting.")
            sys.exit(1)

# Example usage:
unsigned_value = inputUnsignedInt(prompt="Enter a non-negative integer: ", max_val=4294967295) # Max value for uint32
print(f"Unsigned integer: {unsigned_value}")

