import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

def make_secure_request(url):
    """
    Makes a secure HTTP request to the specified URL using best practices.

    Args:
        url (str): The URL to request.

    Returns:
        requests.Response: The response object if the request is successful,
                           None otherwise.  Prints error messages to stderr.
    """

    try:
        # Configure retry strategy for handling transient errors
        retry_strategy = Retry(
            total=3,  # Maximum number of retries
            backoff_factor=1,  # Exponential backoff factor (1 means 1s, 2s, 4s...)
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
            method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"] # Methods to retry
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)

        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)  # Consider removing if only HTTPS is desired

        # Set a reasonable timeout to prevent indefinite hanging
        timeout = 10  # seconds

        # Set a user-agent to identify your application
        headers = {
            'User-Agent': 'MySecureApp/1.0 (Python requests)'
        }

        # Make the request with SSL verification and timeout
        response = http.get(url, headers=headers, timeout=timeout, verify=True)

        # Raise HTTPError for bad responses (4xx or 5xx)
        response.raise_for_status()

        return response

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"Timeout Error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Request Exception: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    url = "https://semmle.com"
    response = make_secure_request(url)

    if response:
        print(f"Request to {url} successful. Status code: {response.status_code}")
        # Process the response content here (e.g., response.text, response.json())
        # Be mindful of the content type and handle it appropriately.
        # For example, if it's JSON:
        # try:
        #     data = response.json()
        #     print(data)
        # except json.JSONDecodeError:
        #     print("Response is not valid JSON.")
    else:
        print(f"Request to {url} failed.")

