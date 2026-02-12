import json
import urllib.request as request
from urllib.error import URLError, HTTPError
import ssl
import urllib.parse
import logging
import idna  # For IDN handling
#import jsonschema # For JSON schema validation (install with pip install jsonschema)
#import io # For potential memory efficiency with large files

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_url_safe(url, allowed_domains=None):
    """
    Validates a URL against a whitelist of allowed domains, including subdomain wildcarding and IDN handling.
    """
    try:
        result = urllib.parse.urlparse(url)
        if result.scheme != 'https':  # Enforce HTTPS
            logging.warning(f"URL {url} is not HTTPS.")
            return False

        if allowed_domains:
            hostname = result.netloc
            try:
                hostname = idna.encode(hostname).decode('ascii')  # Handle IDN
            except idna.IDNAError:
                logging.warning(f"Invalid IDN in URL: {url}")
                return False

            is_allowed = False
            for allowed_domain in allowed_domains:
                if hostname == allowed_domain or hostname.endswith("." + allowed_domain):  # Subdomain wildcard
                    is_allowed = True
                    break

            if not is_allowed:
                logging.warning(f"URL {url} not in allowed domains.")
                return False

        # Add more checks here as needed (e.g., path validation)
        logging.debug(f"URL {url} passed domain validation.") # Example of debug logging
        return True

    except Exception as e:
        logging.error(f"Error parsing URL {url}: {e}")
        return False  # Invalid URL format


def readJSON(url, allowed_domains=None, timeout=10, max_size=1024 * 1024):
    '''
    Read a json file from a url
    and return the parsed json object.

    Handles potential errors like invalid URLs, network issues,
    and invalid JSON content.  Uses HTTPS by default and verifies SSL certificates.
    '''
    if not is_url_safe(url, allowed_domains=allowed_domains):
        logging.warning(f"Unsafe URL: {url}")
        raise ValueError("Invalid or unsafe URL")

    try:
        context = ssl.create_default_context(cafile=None)  # Use system's default CA bundle

        req = request.Request(url, headers={'User-Agent': 'My User Agent'}) # Add a User-Agent header

        with request.urlopen(req, context=context, timeout=timeout) as response:
            if response.getcode() != 200:
                logging.error(f"HTTP error accessing {url}: {response.getcode()} {response.msg}")
                raise HTTPError(url, response.getcode(), response.msg, response.headers, None)

            data = b""
            while True:
                chunk = response.read(4096)  # Read in chunks
                if not chunk:
                    break
                data += chunk
                if len(data) > max_size:
                    logging.error(f"Response exceeds maximum allowed size of {max_size} bytes for URL: {url}")
                    raise ValueError(f"Response exceeds maximum allowed size of {max_size} bytes")


            data = data.decode('utf-8')  # Explicitly decode to UTF-8

            try:
                json_data = json.loads(data)

                # Example JSON Schema Validation (uncomment and adapt)
                # schema = { ... your JSON schema here ... }
                # try:
                #     jsonschema.validate(json_data, schema)
                # except jsonschema.ValidationError as e:
                #     logging.error(f"JSON schema validation failed for {url}: {e}")
                #     raise ValueError(f"Invalid JSON content (schema validation failed) at {url}: {e}")

                logging.info(f"Successfully read JSON from {url}")
                return json_data
            except json.JSONDecodeError as e:
                logging.error(f"Invalid JSON content at {url}: {e}")
                raise ValueError(f"Invalid JSON content at {url}: {e}")

    except HTTPError as e:
        logging.error(f"HTTP error accessing {url}: {e.code} {e.msg}")
        raise ValueError(f"HTTP error accessing {url}: {e.code} {e.msg}")
    except URLError as e:
        logging.error(f"URL error accessing {url}: {e.reason}")
        raise ValueError(f"URL error accessing {url}: {e.reason}")
    except ValueError as e:
        # Re-raise ValueErrors, as they are already handled appropriately
        raise
    except Exception as e:
        logging.exception(f"An unexpected error occurred while processing {url}: {e}") # Log the full traceback
        raise ValueError(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    # Example usage (replace with a valid JSON URL)
    try:
        json_data = readJSON("https://jsonplaceholder.typicode.com/todos/1", allowed_domains=["jsonplaceholder.typicode.com"])  # A safe example URL
        print(json_data)
    except ValueError as e:
        print(f"Error: {e}")

    # Example of an invalid URL
    try:
        json_data = readJSON("invalid_url")
        print(json_data)
    except ValueError as e:
        print(f"Error: {e}")

    # Example of a URL that returns non-JSON data
    try:
        json_data = readJSON("https://www.google.com", allowed_domains=["www.google.com"])
        print(json_data)
    except ValueError as e:
        print(f"Error: {e}")

    # Example of a URL that doesn't exist
    try:
        json_data = readJSON("https://example.com/thispagedoesnotexist", allowed_domains=["example.com"])
        print(json_data)
    except ValueError as e:
        print(f"Error: {e}")

    # Example of an SSRF attempt (will be blocked)
    try:
        json_data = readJSON("file:///etc/passwd")
        print(json_data)
    except ValueError as e:
        print(f"Error: {e}")

