import json
import urllib.parse
import urllib.request as request
from urllib.error import URLError, HTTPError
import socket
import logging
import re  # For Content-Type and JSON structure checks
import time  # For retry mechanism

# Configure logging (replace with your desired configuration)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def readJSON(url, max_retries=3):
    '''
    Read a json file from a url
    and return the parsed json object
    '''

    # --- Security Guidelines Implementation ---

    # 1, 2, 3, 4. URL Validation and Allowlisting:  Validate the URL before making the request.
    # Define a list of allowed hostnames.  Crucially, this should be based on *your* application's requirements.
    # This list should contain *only* the domains that the application *needs* to access.  Avoid overly permissive allowlists.
    allowed_hosts = ["example.com", "api.example.com", "www.example.com"]  # Replace with your allowed hosts!

    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            raise ValueError("Invalid URL: Hostname is missing.")

        # Handle arbitrary subdomain sequences correctly.  Check if the base domain is allowed.
        # For example, if allowed_hosts contains "example.com", then "api.example.com" and "sub.api.example.com" would be allowed, but "evil.com" would not.
        base_domain_allowed = False
        for allowed_host in allowed_hosts:
            if hostname == allowed_host or hostname.endswith("." + allowed_host):
                base_domain_allowed = True
                break

        if not base_domain_allowed:
            raise ValueError(f"URL hostname '{hostname}' is not in the allowed list: {allowed_hosts}")

        if parsed_url.scheme.lower() not in ("http", "https"):
            raise ValueError("Invalid URL scheme. Only HTTP and HTTPS are allowed.")

    except ValueError as e:
        logging.error(f"Invalid URL: {e}")
        return None  # Or raise the exception, depending on desired behavior

    # 5, 6, 7, 8.  Input Validation and Sanitization (applied implicitly by URL validation above)
    # The URL validation above prevents arbitrary URLs from being used.  If you were to pass
    # data *to* the URL (e.g., query parameters), you would need to further validate and sanitize
    # that data to prevent injection attacks.  This example focuses on preventing arbitrary URLs.

    # 9, 10.  HTTP Headers and Cookies (handled at a higher level, e.g., web server configuration)
    # These are typically handled by the web server (e.g., Flask, Django) and are not directly
    # within the scope of this function.  You would configure your web server to set HttpOnly cookies
    # and specify the encoding in the HTTP header.

    for attempt in range(max_retries):
        try:
            with request.urlopen(url, timeout=10) as response:  # Add a timeout
                # Check the HTTP status code
                if response.status >= 400:
                    raise HTTPError(url, response.status, response.reason, response.headers, None)

                # Check the Content-Type header to ensure it's JSON
                content_type = response.headers.get('Content-Type', '').lower()
                if not content_type.startswith('application/json'):  # More robust Content-Type check
                    logging.warning(f"Unexpected Content-Type: '{content_type}' from URL: {url}")
                    # Consider raising an exception here.  A non-JSON content type could indicate an error page, a compromised server, or a potential attack.
                    # You should log the unexpected content type for auditing purposes.
                    # raise ValueError(f"Unexpected Content-Type: {content_type}") # Example of raising an exception


                data = response.read(1024 * 1024).decode('utf-8')  # Explicitly decode as UTF-8, limit size to 1MB

                # Basic JSON structure check (example - use with caution!)
                if not re.match(r'^\s*(\[|\{)', data):
                    logging.warning(f"Possible malformed JSON structure detected from URL: {url}")
                    return None

                json_data = json.loads(data)
                return json_data

        except HTTPError as e:
            logging.error(f"HTTPError: {e.code} {e.reason} for URL: {url}")
            return None
        except URLError as e:
            logging.error(f"URLError: {e.reason} for URL: {url}")
            return None
        except socket.timeout:
            logging.warning(f"Timeout error while accessing URL: {url}. Retrying...")
            time.sleep(2**attempt)  # Exponential backoff
            continue # Retry
        except json.JSONDecodeError as e:
            logging.error(f"JSONDecodeError: Could not decode JSON from URL: {url}. Error: {e}")
            # A JSONDecodeError could also be a sign of a potential attack.  An attacker might be sending malformed JSON.
            return None
        except Exception as e:
            logging.exception(f"An unexpected error occurred: {e}")
            return None

    logging.error(f"Failed to retrieve data from {url} after {max_retries} retries.")
    return None


# Example Usage (replace with your actual URL and allowed hosts)
if __name__ == '__main__':
    url = "https://example.com/data.json"  # Replace with a valid JSON URL
    data = readJSON(url)

    if data:
        print("JSON data loaded successfully:")
        print(data)
    else:
        print("Failed to load JSON data.")

