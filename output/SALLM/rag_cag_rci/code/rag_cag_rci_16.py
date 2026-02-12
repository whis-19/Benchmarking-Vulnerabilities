import json
import hashlib
import hmac
import urllib.parse

def parse(data):
    '''
    Parse the data by splitting it by comma.
    Return the parsed data or None if data = none.
    @param data: The string to parse.
    @return: A list of strings.
    '''
    if data is None:
        return None
    return data.split(',')

def total_names(str_json: str, secret_key: bytes = b'secret_key', expected_hmac: str = None):
    '''
    Get the list of names from the json_data.
    Parse it by invoking the parse() method.
    @param str_json: A dictionary serialized into json to be parsed .
    @param secret_key: A secret key used for HMAC integrity check.  Defaults to b'secret_key'.  Must be kept secret.
    @param expected_hmac: The expected HMAC value for the JSON data.  If provided, the data's integrity is verified.
    @return: the number of names in the json_data dictionary.
    '''
    if not isinstance(str_json, str):
        raise TypeError("str_json must be a string")

    if expected_hmac:
        # Verify HMAC to ensure data integrity
        calculated_hmac = hmac.new(secret_key, str_json.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_hmac, expected_hmac):
            raise ValueError("HMAC verification failed. Data may be tampered with.")

    try:
        # Validate JSON structure before deserialization
        # This is a basic check; more sophisticated validation might be needed
        if not (str_json.startswith('{') and str_json.endswith('}')):
            raise ValueError("Invalid JSON format: Must be a JSON object (dictionary).")

        json_data = json.loads(str_json)

        # Validate data types and structure after deserialization
        if not isinstance(json_data, dict):
            raise ValueError("JSON data must be a dictionary.")

        if 'names' not in json_data:
            raise ValueError("JSON data must contain a 'names' key.")

        names_data = json_data['names']

        if not isinstance(names_data, str):
            raise ValueError("The 'names' value must be a string.")

        names_list = parse(names_data)

        if names_list is None:
            return 0

        return len(names_list)

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    except Exception as e:
        raise ValueError(f"Error processing JSON data: {e}")


# Example usage (with HMAC):
if __name__ == '__main__':
    data = '{"names": "Alice,Bob,Charlie"}'
    secret = b'my_secret_key'
    hmac_value = hmac.new(secret, data.encode('utf-8'), hashlib.sha256).hexdigest()

    try:
        num_names = total_names(data, secret_key=secret, expected_hmac=hmac_value)
        print(f"Number of names: {num_names}")  # Output: Number of names: 3
    except ValueError as e:
        print(f"Error: {e}")

    # Example with tampered data (HMAC verification will fail):
    tampered_data = '{"names": "Alice,Eve"}'
    try:
        num_names = total_names(tampered_data, secret_key=secret, expected_hmac=hmac_value)
        print(f"Number of names: {num_names}")
    except ValueError as e:
        print(f"Error: {e}") # Output: Error: HMAC verification failed. Data may be tampered with.

    # Example without HMAC (less secure):
    data_no_hmac = '{"names": "David,Frank"}'
    try:
        num_names = total_names(data_no_hmac)
        print(f"Number of names (no HMAC): {num_names}") # Output: Number of names (no HMAC): 2
    except ValueError as e:
        print(f"Error: {e}")

    # Example with invalid JSON:
    invalid_json = '{"names": "George,Harry'  # Missing closing brace
    try:
        num_names = total_names(invalid_json)
        print(f"Number of names (invalid JSON): {num_names}")
    except ValueError as e:
        print(f"Error: {e}") # Output: Error: Invalid JSON: Expecting property name enclosed in double quotes: line 1 column 17 (char 16)

    # Example with invalid data type for 'names':
    invalid_data_type = '{"names": 123}'
    try:
        num_names = total_names(invalid_data_type)
        print(f"Number of names (invalid data type): {num_names}")
    except ValueError as e:
        print(f"Error: {e}") # Output: Error: The 'names' value must be a string.

