import pickle
import io
import os
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

BASE_DATA_DIR = "data"  # Define a safe base directory
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit


def load_data(file_path):
    '''
    Deserializes the string data in the file located at file_path.
    Uses a safer unpickling approach to mitigate security risks.
    @param file_path: The path to a file containing a  string to  deserialize.
    @return: The deserialized string or None if the deserialization fails or if the file contains unsafe objects.
    '''
    try:
        # Sanitize file path to prevent path traversal
        file_path = os.path.abspath(os.path.normpath(os.path.join(BASE_DATA_DIR, file_path)))

        # Check if the file is within the allowed base directory
        if not file_path.startswith(os.path.abspath(BASE_DATA_DIR)):
            logging.error(f"File path is outside the allowed directory: {file_path}")
            return None

        # Check file size (prevent DoS)
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            logging.error(f"File size exceeds the maximum allowed size: {file_size} bytes")
            return None

        with open(file_path, 'rb') as f:
            data = f.read()
            data_io = io.BytesIO(data)

            class RestrictedUnpickler(pickle.Unpickler):
                __slots__ = ()

                def find_class(self, module, name):
                    # Whitelist: Only allow unpickling strings
                    if module == 'builtins' and name == 'str':
                        return str
                    elif module == '__builtin__' and name == 'str':
                        return str
                    else:
                        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden")

            unpickler = RestrictedUnpickler(data_io)
            deserialized_data = unpickler.load()

            if isinstance(deserialized_data, str):
                return deserialized_data
            else:
                logging.warning("Deserialized data is not a string. Returning None.")
                return None

    except pickle.UnpicklingError as e:
        logging.error(f"Unpickling error loading data from {file_path}: {e}")
        return None
    except AttributeError as e:
        logging.error(f"AttributeError loading data from {file_path}: {e}")
        return None
    except ImportError as e:
        logging.error(f"ImportError loading data from {file_path}: {e}")
        return None
    except EOFError as e:
        logging.error(f"EOFError loading data from {file_path}: {e}")
        return None
    except FileNotFoundError as e:
        logging.error(f"File not found: {file_path}: {e}")
        return None
    except OSError as e:
        logging.error(f"OSError loading data from {file_path}: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred loading data from {file_path}: {e}")
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
            # Sanitize file path to prevent path traversal
            file_path = os.path.abspath(os.path.normpath(os.path.join(BASE_DATA_DIR, file_path)))

            # Check if the file is within the allowed base directory
            if not file_path.startswith(os.path.abspath(BASE_DATA_DIR)):
                logging.error(f"File path is outside the allowed directory: {file_path}")
                return

            # Ensure the directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, 'wb') as f:
                pickle.dump(data, f)
            logging.info(f"Data successfully saved to {file_path}")
        except OSError as e:
            logging.error(f"OSError saving data to {file_path}: {e}")
        except Exception as e:
            logging.exception(f"Error saving data to {file_path}: {e}")
    else:
        logging.warning("Input data is not a string.  Data not saved.")


if __name__ == '__main__':
    # Example usage:

    # Save data
    data_to_save = "This is a test string."
    file_path = "test.ser"  # Relative path within the BASE_DATA_DIR
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
    save_data(123, "numbers.ser") # This will print a warning and not save the data.

