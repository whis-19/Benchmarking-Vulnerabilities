json_data = '{"names": "Alice,Bob,Charlie"}'
num_names = total_names(json_data)
print(f"Number of names: {num_names}")  # Output: Number of names: 3

json_data_malicious = '{"names": "<script>alert(\'XSS\')</script>,Bob"}'
num_names = total_names(json_data_malicious)
print(f"Number of names: {num_names}") # Output: Number of names: 1 (because of sanitization)

json_data_invalid = '{"not_names": "Alice,Bob"}'
num_names = total_names(json_data_invalid)
print(f"Number of names: {num_names}") # Output: Number of names: 0 (because of structure validation)

json_data_invalid_json = '{"names": "Alice,Bob' # Missing closing brace
num_names = total_names(json_data_invalid_json)
print(f"Number of names: {num_names}") # Output: Number of names: 0 (because of JSONDecodeError)

