import os
import stat
import logging
import json  # Example for JSON validation
import jsonschema # Example for JSON validation
import re # For regular expression validation

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_path_within_allowed(file_path, allowed_locations):
    file_path = os.path.abspath(file_path)
    for allowed_location in allowed_locations:
        allowed_location = os.path.abspath(allowed_location)
        try:
            common_path = os.path.commonpath([file_path, allowed_location])
            if common_path == allowed_location:
                return True
        except ValueError:
            pass
    return False

def validate_json_config(content):
    try:
        data = json.loads(content)
        schema = {  # Define your schema here
            "type": "object",
            "properties": {
                "setting1": {"type": "string"},
                "setting2": {"type": "integer"}
            },
            "required": ["setting1", "setting2"]
        }
        jsonschema.validate(instance=data, schema=schema)
        return data  # Return the validated data
    except (json.JSONDecodeError, jsonschema.ValidationError) as e:
        logging.error(f"Error: Invalid configuration content: {e}")
        return None  # Or raise an exception

def validate_ipv4_address(ip_address):
    pattern = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if re.match(pattern, ip_address):
        return True
    else:
        return False


def secure_write_config(file_path, content):
    if not isinstance(file_path, str):
        logging.error("Error: File path must be a string.")
        return False

    file_path = os.path.abspath(file_path)
    file_path = os.path.normpath(file_path)

    if ".." in file_path:
        logging.error("Error: Path traversal detected.  File path cannot contain '..'.")
        return False

    allowed_extensions = [".conf", ".cfg", ".ini", ".json"]  # Added .json
    # Example of using environment variables for allowed locations:
    allowed_locations_env = os.environ.get("MYAPP_ALLOWED_LOCATIONS", "/etc/myapp/,~/.myapp/")
    allowed_locations = [os.path.expanduser(loc.strip()) for loc in allowed_locations_env.split(",")]

    file_extension = os.path.splitext(file_path)[1]
    if file_extension not in allowed_extensions:
        logging.error(f"Error: File extension '{file_extension}' is not allowed. Allowed extensions: {allowed_extensions}")
        return False

    if not is_path_within_allowed(file_path, allowed_locations):
        logging.error(f"Error: File location '{file_path}' is not allowed. Allowed locations: {allowed_locations}")
        return False

    file_directory = os.path.dirname(file_path)
    try:
        os.makedirs(file_directory, exist_ok=True)
    except OSError as e:
        logging.error(f"Error: Could not create directory: {e}")
        return False

    # Content Validation (Example for JSON)
    if file_extension == ".json":
        validated_content = validate_json_config(content)
        if validated_content is None:
            return False
        content_to_write = json.dumps(validated_content)  # Write back the validated content
    else:
        content_to_write = content # No validation for other file types (yet!)

    try:
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            # Optionally set ownership (replace uid and gid with appropriate values).
            # This ensures the file is owned by the appropriate user and group,
            # which is crucial in multi-user environments for access control.
            # NOTE: This requires the process to have sufficient privileges (e.g., root).
            # Attempting to use os.fchown without the necessary privileges will result in an OSError.
            # os.fchown(fd, uid, gid)

            os.write(fd, content_to_write.encode('utf-8')) # UTF-8 is generally the preferred encoding
        finally:
            os.close(fd)
        return True
    except OSError as e:
        logging.error(f"Error: Error writing to file: {e}")
        return False

# Example Usage:
file_path = "./config/important_config.conf"  # Example file path
config_content = "important_config data here"

if secure_write_config(file_path, config_content):
    print("Configuration file written successfully.")
else:
    print("Failed to write configuration file.")

# Example with JSON
json_file_path = "./config/important_config.json"
json_config_content = '{"setting1": "value1", "setting2": 123}'

if secure_write_config(json_file_path, json_config_content):
    print("JSON Configuration file written successfully.")
else:
    print("Failed to write JSON configuration file.")


# Example of an attempt to write to an invalid location:
invalid_file_path = "../../../tmp/evil_config.conf"
if secure_write_config(invalid_file_path, "evil data"):
    print("Configuration file written successfully.")
else:
    print("Failed to write configuration file (as expected).")

# Example of an attempt to write to a file with an invalid extension:
invalid_extension_path = "./config/important_config.exe"
if secure_write_config(invalid_extension_path, "evil data"):
    print("Configuration file written successfully.")
else:
    print("Failed to write configuration file (as expected).")

# Example of IPv4 address validation
ip_address = "192.168.1.1"
if validate_ipv4_address(ip_address):
    print(f"{ip_address} is a valid IPv4 address")
else:
    print(f"{ip_address} is not a valid IPv4 address")

