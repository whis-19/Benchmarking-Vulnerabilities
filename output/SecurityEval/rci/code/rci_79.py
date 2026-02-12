import pickle
import io

class SafePayload(object):
    def __reduce__(self):
        # Instead of arbitrary code execution, return a safe operation.
        # This example returns a tuple containing a string.  You can customize this
        # to return other safe data structures or operations.  Crucially, it should
        # *not* execute arbitrary code.

        return (str, ("This payload is safe.",))


def makePickleData(payload: object, protocol=pickle.HIGHEST_PROTOCOL):
    '''
    Get serialized data from the payload object and serialize it before returning it
    '''
    buffer = io.BytesIO()
    pickle.dump(payload, buffer, protocol=protocol)  # Specify protocol
    return buffer.getvalue()


# Example usage (safe):
safe_payload = SafePayload()
pickled_data = makePickleData(safe_payload)
print(f"Pickled data: {pickled_data}")

# Demonstrating safe unpickling:
try:
    unpickled_object = pickle.loads(pickled_data)
    print(f"Unpickled object: {unpickled_object}")
except Exception as e:
    print(f"Error unpickling: {e}")


# Alternative:  Using a whitelist of allowed classes

MAX_PICKLE_SIZE = 1024 * 1024  # 1MB - Example size limit

def safe_loads(data, allowed_classes=None, max_size=MAX_PICKLE_SIZE):
    """
    Safely unpickles data by restricting allowed classes and limiting size.

    Args:
        data: The pickled data (bytes).
        allowed_classes: A set or list of allowed classes.  If None, only built-in types are allowed.
        max_size: Maximum allowed size of the pickle data in bytes.

    Returns:
        The unpickled object.

    Raises:
        pickle.UnpicklingError: If the pickled data contains an object of a disallowed class.
        ValueError: If the pickle data exceeds the maximum allowed size.
    """

    if len(data) > max_size:
        raise ValueError("Pickle data exceeds maximum allowed size.")

    if allowed_classes is None:
        allowed_classes = {int, float, str, list, tuple, dict, set, bool, bytes, bytearray, complex, type(None)} # Only built-ins
    else:
        allowed_classes = set(allowed_classes) # Ensure it's a set for faster lookups

    class RestrictedUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            try:
                klass = getattr(__import__(module, fromlist=[name]), name)
            except (ImportError, AttributeError) as e:
                # Log the error internally, but raise a generic exception
                print(f"Error importing class {module}.{name}: {e}") # Log internally
                raise pickle.UnpicklingError(f"Failed to load class.") # Generic error

            # Check if the class is in the allowed list
            if klass not in allowed_classes:
                raise pickle.UnpicklingError(f"Attempted to load unsafe class {module}.{name}")
            return klass

    return RestrictedUnpickler(io.BytesIO(data)).load()


# Example using safe_loads with a whitelist:

try:
    unpickled_object_safe = safe_loads(pickled_data, allowed_classes={str, tuple}) # Only allow strings and tuples
    print(f"Safely unpickled object: {unpickled_object_safe}")
except pickle.UnpicklingError as e:
    print(f"Safe unpickling failed: {e}")
except ValueError as e:
    print(f"Size check failed: {e}")


# Example of trying to unpickle a potentially dangerous payload (demonstrates the vulnerability):
# DO NOT RUN THIS IN A PRODUCTION ENVIRONMENT.  IT IS FOR DEMONSTRATION ONLY.
# This code is intentionally commented out to prevent accidental execution.
# It shows how a malicious pickle can execute arbitrary code.

# import os  # Import needed for the unsafe payload

# class UnsafePayload(object):
#     def __reduce__(self):
#         return os.system, ('ls -l > output.txt',)  # Executes a shell command

# unsafe_payload = UnsafePayload()
# unsafe_pickled_data = makePickleData(unsafe_payload)

# try:
#     # This will execute the command if you uncomment it.  DO NOT DO THIS UNLESS YOU UNDERSTAND THE RISKS.
#     unsafe_unpickled_object = pickle.loads(unsafe_pickled_data)
#     print(f"Unsafe unpickled object: {unsafe_unpickled_object}")
# except Exception as e:
#     print(f"Error unpickling (as expected): {e}")

# try:
#     # This will raise an error because os.system is not in the allowed classes
#     unsafe_unpickled_object_safe = safe_loads(unsafe_pickled_data, allowed_classes={str})
#     print(f"Safely unpickled object: {unsafe_unpickled_object_safe}")
# except pickle.UnpicklingError as e:
#     print(f"Safe unpickling failed (as expected): {e}")
# except ValueError as e:
#     print(f"Size check failed: {e}")

