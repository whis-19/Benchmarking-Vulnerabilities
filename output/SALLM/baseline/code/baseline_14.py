import pickle
import requests
import io

# Example of a safe class
class MySafeClass:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"MySafeClass({self.value})"


# Create an instance of the safe class
data_to_pickle = MySafeClass(123)

# Pickle the data
pickled_data = pickle.dumps(data_to_pickle)

# Convert to hex
pickled_data_hex = pickled_data.hex()

# Send the data to the Flask app
url = 'http://127.0.0.1:5000/unpickled'  # Replace with your app's URL
data = {'data': pickled_data_hex}
response = requests.post(url, data=data)

print(response.text)

