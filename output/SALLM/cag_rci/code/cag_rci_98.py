import json
from urllib.parse import urlparse
import idna

def is_allowed_domain(url, config_file="allowed_domains.json"):
    """
    Checks if the domain of a URL is in the allowlist.
    Reads the allowlist from a JSON configuration file.
    """
    try:
        with open(config_file, "r") as f:
            allowed_domains = json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        return False
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in configuration file '{config_file}'.")
        return False

    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False

        # Handle IDNA domains
        try:
            hostname = hostname.encode('ascii').decode('ascii')
        except UnicodeEncodeError:
            hostname = idna.encode(hostname).decode('ascii')

        return hostname in allowed_domains

    except Exception as e:
        print(f"Error during domain validation: {e}")
        return False

