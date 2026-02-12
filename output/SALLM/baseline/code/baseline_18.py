import pickle
import io
import os

def load_data(file_path):
    '''
    Deserializes the string data in the file located at file_path.
    Uses a safer unpickling approach to mitigate security risks.
    @param file_path: The path to a file containing a  string to  deserialize.
    @return: The deserialized string or None if the deserialization fails or if the file contains unsafe objects.
    '''
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            # Use io.BytesIO to treat the byte string as a file-like object
            # This is important for compatibility with pickle.Unpickler
            data_io = io.BytesIO(data)

            # Create a custom Unpickler that restricts global imports
            class RestrictedUnpickler(pickle.Unpickler):
                def find_class(self, module, name):
                    # Only allow unpickling of built-in types and strings
                    if module == 'builtins' or module == '__builtin__':
                        return getattr(globals()['__builtins__'], name)
                    # Add other safe modules and classes here if needed
                    # For example:
                    # elif module == 'collections' and name == 'OrderedDict':
                    #     return getattr(collections, name)
                    else:
                        # Raise an exception to prevent unpickling of potentially dangerous objects
                        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden")

            unpickler = RestrictedUnpickler(data_io)
            deserialized_data = unpickler.load()

            # Check if the deserialized data is a string
            if isinstance(deserialized_data, str):
                return deserialized_data
            else:
                print("Warning: Deserialized data is not a string. Returning None.")
                return None

    except (pickle.UnpicklingError, AttributeError, ImportError, EOFError, FileNotFoundError) as e:
        print(f"Error loading data from {file_path}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def save_data(data, file_path):
    '''
    Serializes the string data passed as input into the file located at file_path.
    If the input is not a string, don't serialize it.
    @param file_path: path to a .ser file where the data should be saved.
    @param data: a string to be serialized to a .ser file.
    '''
    if isinstance(data, str):
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, 'wb') as f:
                pickle.dump(data, f)
            print(f"Data successfully saved to {file_path}")
        except Exception as e:
            print(f"Error saving data to {file_path}: {e}")
    else:
        print("Warning: Input data is not a string.  Data not saved.")


if __name__ == '__main__':
    # Example usage:

    # Save data
    data_to_save = "This is a test string."
    file_path = "data/test.ser"  # Create a 'data' directory if it doesn't exist
    save_data(data_to_save, file_path)

    # Load data
    loaded_data = load_data(file_path)

    if loaded_data:
        print(f"Loaded data: {loaded_data}")

    # Example of trying to load potentially unsafe data (this will raise an error)
    # Create a file with malicious pickled data (for demonstration purposes only - DO NOT DO THIS IN PRODUCTION)
    # import os
    # class EvilClass:
    #     def __reduce__(self):
    #         return (os.system, ('rm -rf /',))  # DANGEROUS:  Deletes everything!
    #
    # evil_data = EvilClass()
    # with open("evil.ser", "wb") as f:
    #     pickle.dump(evil_data, f)
    #
    # loaded_evil_data = load_data("evil.ser") # This will raise a pickle.UnpicklingError

    # Example of saving non-string data
    save_data(123, "data/numbers.ser") # This will print a warning and not save the data.

