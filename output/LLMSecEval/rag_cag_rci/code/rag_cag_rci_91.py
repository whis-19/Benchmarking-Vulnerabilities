import requests
try:
    response = requests.get('https://example.com', verify=True) #verify=True enables certificate validation
    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
    # ... process the response
except requests.exceptions.RequestException as e:
    print(f"Error during HTTPS request: {e}")

