import json
import urllib.request as request
from urllib.error import URLError, HTTPError
import ssl

def readJSON(url):
    '''
    Read a json file from a url
    and return the parsed json object.

    Handles potential network errors and SSL verification issues.
    '''
    try:
        # Create an SSL context that bypasses certificate verification.
        # This is generally NOT recommended for production, but included
        # for cases where you absolutely trust the source and need to
        # bypass certificate issues.  Consider fixing the certificate
        # issue instead of disabling verification.
        # ssl_context = ssl.create_default_context()
        # ssl_context.check_hostname = False
        # ssl_context.verify_mode = ssl.CERT_NONE

        # Use the SSL context in the request.  If you don't need to bypass
        # verification, remove the 'context' argument.
        # with request.urlopen(url, context=ssl_context) as response:

        # Default and recommended approach:  Verify SSL certificates.
        with request.urlopen(url) as response:
            data = response.read()
            encoding = response.info().get_content_charset('utf-8')  # Get encoding, default to utf-8
            json_data = json.loads(data.decode(encoding))
            return json_data

    except HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason} for URL: {url}")
        return None  # Or raise the exception, depending on desired behavior

    except URLError as e:
        print(f"URL Error: {e.reason} for URL: {url}")
        return None  # Or raise the exception

    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: Invalid JSON format at URL: {url} - {e}")
        return None # Or raise the exception

    except Exception as e:
        print(f"An unexpected error occurred: {e} for URL: {url}")
        return None # Or raise the exception


if __name__ == '__main__':
    # Example usage (replace with a real URL)
    url = "https://jsonplaceholder.typicode.com/todos/1"  # A safe example URL
    # url = "https://self-signed.badssl.com/" # Example of a URL with SSL issues (for testing)
    # url = "https://httpstat.us/500" # Example of a URL that returns a 500 error (for testing)
    # url = "https://example.com/nonexistent.json" # Example of a URL that doesn't exist (for testing)
    # url = "https://example.com" # Example of a URL that returns HTML instead of JSON (for testing)

    data = readJSON(url)

    if data:
        print("JSON data:")
        print(json.dumps(data, indent=4))  # Pretty print the JSON
    else:
        print("Failed to retrieve or parse JSON data.")

