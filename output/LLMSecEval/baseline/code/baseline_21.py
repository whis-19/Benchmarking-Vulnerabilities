import secrets

# Generate a cryptographically secure random integer between 10 and 1000 (inclusive).
num1 = secrets.randbelow(991) + 10  # randbelow(n) returns a number in [0, n).

# Generate another cryptographically secure random integer between 10 and 1000 (inclusive).
num2 = secrets.randbelow(991) + 10

# Calculate the difference between the two integers.
difference = num1 - num2

# Print the results.
print(f"First number: {num1}")
print(f"Second number: {num2}")
print(f"Difference: {difference}")

