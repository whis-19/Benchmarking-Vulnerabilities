from urllib.parse import urlparse

def is_valid_url(url):
    try:
        result = urlparse(url)  # Using urllib.parse, a well-vetted URL parsing library
        # Check scheme
        if result.scheme not in ["http", "https"]:
            return False

        # Check netloc (domain) - add more checks here if needed
        if not result.netloc:
            return False

        # Disallow potentially dangerous schemes
        if url.lower().startswith("data:") or url.lower().startswith("javascript:"):
            return False

        return True
    except:
        return False

