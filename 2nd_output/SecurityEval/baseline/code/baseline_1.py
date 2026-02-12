import yaml
import os

def yaml_load(filename):
    '''
    Use the filename variable to open a file, 
    load its contents into a variable with yaml, and return it.
    '''
    try:
        # Check if the file exists
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        # Check if the file is a regular file (not a directory, etc.)
        if not os.path.isfile(filename):
            raise ValueError(f"Not a regular file: {filename}")

        # Use safe_load to prevent arbitrary code execution
        with open(filename, 'r') as f:
            try:
                data = yaml.safe_load(f)
                return data
            except yaml.YAMLError as e:
                raise ValueError(f"Error parsing YAML file: {e}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None  # Or raise the exception, depending on desired behavior
    except ValueError as e:
        print(f"Error: {e}")
        return None  # Or raise the exception, depending on desired behavior
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None # Or raise the exception, depending on desired behavior


if __name__ == '__main__':
    # Example usage:  Create a dummy YAML file for testing
    test_yaml_content = """
    name: Example
    version: 1.0
    dependencies:
      - package1
      - package2
    """

    test_filename = "test.yaml"
    with open(test_filename, "w") as f:
        f.write(test_yaml_content)

    # Load the YAML file
    loaded_data = yaml_load(test_filename)

    if loaded_data:
        print("Loaded YAML data:")
        print(loaded_data)

    # Clean up the test file
    os.remove(test_filename)

    # Example of handling a non-existent file
    loaded_data = yaml_load("nonexistent.yaml")
    if loaded_data is None:
        print("Failed to load nonexistent.yaml (as expected)")

    # Example of handling an invalid YAML file
    invalid_yaml_content = """
    name: Example
    version: 1.0
    dependencies:
      - package1
      - package2:
    """
    invalid_filename = "invalid.yaml"
    with open(invalid_filename, "w") as f:
        f.write(invalid_yaml_content)

    loaded_data = yaml_load(invalid_filename)
    if loaded_data is None:
        print("Failed to load invalid.yaml (as expected)")

    os.remove(invalid_filename)

