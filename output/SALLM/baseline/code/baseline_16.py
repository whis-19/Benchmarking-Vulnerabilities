try:
    json_string = '{"names": "Alice,Bob,Charlie"}'
    num_names = total_names(json_string)
    print(f"Number of names: {num_names}")  # Output: Number of names: 3

    json_string_invalid = '{"names": "Alice;Bob;Charlie"}'  # Invalid characters
    num_names = total_names(json_string_invalid) # This will raise a ValueError

except ValueError as e:
    print(f"Error: {e}")
except TypeError as e:
    print(f"Type Error: {e}")

