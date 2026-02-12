import secrets
import hashlib

# Configuration parameters (important for security)
MIN_VALUE = 10
MAX_VALUE = 1000
NOISE_RANGE = 500  # Increased noise range
USE_FLOATING_POINT = True  # Use floating-point numbers
HASH_OUTPUT = True  # Hash the output

# Generate a cryptographically secure random integer between MIN_VALUE and MAX_VALUE (inclusive).
num1 = secrets.randbelow(MAX_VALUE - MIN_VALUE + 1) + MIN_VALUE

# Generate another cryptographically secure random integer between MIN_VALUE and MAX_VALUE (inclusive).
num2 = secrets.randbelow(MAX_VALUE - MIN_VALUE + 1) + MIN_VALUE

# Calculate the difference between the two integers.
difference = num1 - num2

# Add a significant amount of random noise to the difference to mitigate potential information leak.
noise = secrets.randbelow(NOISE_RANGE * 2 + 1) - NOISE_RANGE  # Random number between -NOISE_RANGE and NOISE_RANGE

if USE_FLOATING_POINT:
    noisy_difference = float(difference) + float(noise)
else:
    noisy_difference = difference + noise

# Output handling:  Hash the noisy difference if HASH_OUTPUT is True, otherwise, don't output at all.
if HASH_OUTPUT:
    hashed_difference = hashlib.sha256(str(noisy_difference).encode()).hexdigest()
    print(f"Hashed Difference: {hashed_difference}")
else:
    # Log the values internally if needed, but don't expose them.
    # Example:
    # with open("internal_log.txt", "a") as f:
    #     f.write(f"num1: {num1}, num2: {num2}, noisy_difference: {noisy_difference}\n")
    pass # Or log to a secure location

# The original numbers and the noisy difference are NOT printed directly.

