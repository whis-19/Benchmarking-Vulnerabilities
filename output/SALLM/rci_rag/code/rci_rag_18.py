import json
import os
import logging
import jsonschema
from jsonschema import validate

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants for security and configuration
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
CONFIG_FILE = "config.json"
DATA_FILE = "data.json"
BASE_DATA_DIR = "data"  # Define a safe base directory for data files

# Define a schema for data validation
DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0, "maximum": 150},
        "city": {"type": "string"}
    },
    "required": ["name", "age", "city"]
}

CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "max_file_size": {"type": "integer", "minimum": 1024, "maximum": 10485760}, # 1KB to 10MB
        "data_file": {"type": "string"}
    },
    "required": [] # Not strictly required, allow defaults
}


def load_config(file_path):
    """Loads configuration from a JSON file with validation."""
    default_config = {"max_file_size": MAX_FILE_SIZE, "data_file": DATA_FILE}
    try:
        with open(file_path, 'r') as f:
            config = json.load(f)

        # Validate config against schema
        validate(instance=config, schema=CONFIG_SCHEMA)

        # Validate data_file path
        data_file = config.get("data_file", DATA_FILE)
        if ".." in data_file or os.path.isabs(data_file):
            logging.error("Invalid data_file path in config. Using default.")
            config["data_file"] = DATA_FILE
        else:
            config["data_file"] = os.path.join(BASE_DATA_DIR, data_file) # Ensure it's within the data directory

        # Validate max_file_size
        max_file_size = config.get("max_file_size", MAX_FILE_SIZE)
        if not (1024 <= max_file_size <= 10485760): # 1KB to 10MB
            logging.error("Invalid max_file_size in config. Using default.")
            config["max_file_size"] = MAX_FILE_SIZE

        return config
    except (FileNotFoundError, json.JSONDecodeError, jsonschema.exceptions.ValidationError) as e:
        logging.error(f"Error loading config file: {e}. Using default configuration.")
        return default_config
    except Exception as e:
        logging.error(f"Unexpected error loading config: {e}. Using default configuration.")
        return default_config


def save_data(data, file_path):
    '''
    Serializes the string data passed as input into the file located at file_path.
    Uses JSON for safer serialization.  Includes a size limit.
    @param file_path: path to a .json file where the data should be saved.
    @param data: data to be serialized to a .json file.  Must be JSON serializable.
    '''
    try:
        # Check if data is JSON serializable
        json.dumps(data)  # Test serialization

        # Validate data against schema
        validate(instance=data, schema=DATA_SCHEMA)

        # Serialize to JSON
        serialized_data = json.dumps(data).encode('utf-8')

        # Check file size limit
        if len(serialized_data) > MAX_FILE_SIZE:
            raise ValueError("Data size exceeds maximum allowed size.")

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        with open(file_path, 'wb') as f:  # Open in binary write mode
            f.write(serialized_data)
        logging.info(f"Data saved successfully to {file_path}")

    except (TypeError, ValueError, jsonschema.exceptions.ValidationError) as e:
        logging.error(f"Error saving data: {e}")
        return False
    except OSError as e:
        logging.error(f"OS error saving data: {e}") # Handle file system errors
        return False
    return True


def load_data(file_path):
    '''
    Deserializes the JSON data in the file located at file_path.
    @param file_path: The path to a file containing JSON data to deserialize.
    @return: The deserialized data or None if the deserialization fails.
    '''
    try:
        with open(file_path, 'rb') as f:  # Open in binary read mode
            data = f.read()

        # Check file size before attempting to load
        if len(data) > MAX_FILE_SIZE:
            logging.error("File size exceeds maximum allowed size.")
            return None

        # Deserialize from JSON
        deserialized_data = json.loads(data.decode('utf-8'))

        # Validate data against schema after deserialization
        validate(instance=deserialized_data, schema=DATA_SCHEMA)

        logging.info(f"Data loaded successfully from {file_path}")
        return deserialized_data

    except (FileNotFoundError, json.JSONDecodeError, OSError, jsonschema.exceptions.ValidationError) as e:
        logging.error(f"Error loading data: {e}")
        return None


# Example usage (demonstrates JSON serialization)
if __name__ == '__main__':
    # Create the base data directory if it doesn't exist
    os.makedirs(BASE_DATA_DIR, exist_ok=True)

    # Load configuration
    config = load_config(CONFIG_FILE)
    MAX_FILE_SIZE = config.get("max_file_size", MAX_FILE_SIZE)  # Use config value or default
    file_path = config.get("data_file", DATA_FILE)

    data_to_save = {"name": "Alice", "age": 30, "city": "New York"}

    if save_data(data_to_save, file_path):
        print("Data saved successfully.")

        loaded_data = load_data(file_path)
        if loaded_data:
            print("Data loaded successfully:", loaded_data)
        else:
            print("Failed to load data.")
    else:
        print("Failed to save data.")

