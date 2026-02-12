if not re.match(r"^\d+$", sanitized_input):  # No negative sign allowed
       raise ValueError("Invalid input: Input must be a non-negative integer.")
   integer_value = abs(int(sanitized_input))

