import pickle
import io
import os
import subprocess

class SafePayload(object):
    def __reduce__(self):
        # Instead of executing arbitrary code, return a safe operation.
        # This example returns a tuple containing a safe function and its arguments.
        # You can customize this to perform a specific, safe task.
        return (self.safe_operation, ("This is a safe operation",))

    def safe_operation(self, message):
        """
        A safe operation that does not execute arbitrary code.
        """
        print(f"Safe operation: {message}")
        return message  # Or perform some other safe task

def makePickleData(payload: SafePayload):
    '''
    Get serialized data from the payload object and serialize it before returning it
    '''
    buffer = io.BytesIO()
    pickle.dump(payload, buffer)
    return buffer.getvalue()


# Example usage (safe):
if __name__ == '__main__':
    safe_payload = SafePayload()
    pickle_data = makePickleData(safe_payload)

    # Simulate receiving the pickled data (from a file, network, etc.)
    # IMPORTANT:  Never unpickle data from untrusted sources!
    # This is ONLY for demonstration purposes with the SAFE payload.
    try:
        loaded_payload = pickle.loads(pickle_data)
        print("Payload loaded successfully.")
    except Exception as e:
        print(f"Error loading payload: {e}")


# Example of how to avoid using pickle altogether (recommended):
def serialize_data(data):
    """
    Serializes data to JSON format.  JSON is generally safer than pickle.
    """
    import json
    return json.dumps(data)

def deserialize_data(data):
    """
    Deserializes data from JSON format.
    """
    import json
    return json.loads(data)


    # Example usage with JSON:
    data_to_serialize = {"message": "Hello, world!"}
    serialized_data = serialize_data(data_to_serialize)
    deserialized_data = deserialize_data(serialized_data)
    print(f"Original data: {data_to_serialize}")
    print(f"Deserialized data: {deserialized_data}")

