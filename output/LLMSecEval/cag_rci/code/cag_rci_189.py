import re

ALLOWED_DOMAINS_STRING = os.environ.get("ALLOWED_DOMAINS", "example.com,example.net")
ALLOWED_DOMAINS = [d.strip() for d in ALLOWED_DOMAINS_STRING.split(",")]
ALLOWED_DOMAINS_REGEX = re.compile(r"^(" + "|".join(re.escape(d) for d in ALLOWED_DOMAINS) + r")$")

def is_allowed_domain(domain):
    return bool(ALLOWED_DOMAINS_REGEX.match(domain))

def sanitize_url(url):
    try:
        parsed_url = urlparse(url)
        if not is_allowed_domain(parsed_url.netloc):
            return None
        # ... rest of the sanitize_url function ...
    except:
        return None

