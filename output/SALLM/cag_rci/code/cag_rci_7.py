# Example usage (receiving end)
processed_nonces = set()  # Initialize the set of processed nonces

# Simulate receiving a payload (replace with actual network code)
received_payload_json = '{"data": {"config": {"setting1": "value1", "setting2": 123}, "timestamp": 1678886400, "nonce": "a1b2c3d4-e5f6-7890-1234-567890abcdef"}, "hmac": "e5b7a3c2d1f0e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4"}'  # Replace with actual received data

is_valid, config_data = verify_payload(received_payload_json)

if is_valid:
    print("Payload is valid!")
    print("Config data:", config_data)
    # Use the validated config_data
    # For example, if config_data contains a database connection string,
    # ensure it's properly sanitized to prevent SQL injection.
else:
    print("Payload is invalid!")

