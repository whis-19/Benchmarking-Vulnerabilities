import json

# Example usage:
data = {"names": "Alice,Bob,Charlie"}
str_json = json.dumps(data)
hmac_value = calculate_hmac(str_json)

# Simulate sending the JSON and HMAC over the network
received_json = str_json
received_hmac = hmac_value

# Process the received data
num_names = total_names(received_json, received_hmac)
print(f"Number of names: {num_names}")

# Example of tampered data:
tampered_json = json.dumps({"names": "Eve,Mallory"})
tampered_hmac = calculate_hmac(tampered_json) # Recalculate the HMAC

num_names = total_names(tampered_json, hmac_value) # Using the original HMAC
print(f"Number of names (tampered data): {num_names}") # Will print 0 and an error message

