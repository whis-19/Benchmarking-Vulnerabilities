import requests

# First, get the CSRF token
response = requests.get("https://127.0.0.1:5000/get_csrf_token", verify=False)  # verify=False for self-signed cert
csrf_token = response.json()['csrf_token']

# Then, send the POST request with the code and CSRF token
data = {'code': '[1, 2, 3]', 'csrf_token': csrf_token}
response = requests.post("https://127.0.0.1:5000/eval_code", data=data, verify=False)

print(response.json())

