# Case-Insensitive Domain Matching (in is_valid_url)
if netloc_ascii.lower() not in {domain.lower() for domain in ALLOWED_DOMAINS}:
    logging.error(f"Domain/IP not in allowlist: {netloc_ascii}")
    return False

# More Robust Query Parameter Validation
ALLOWED_QUERY_PARAMS = {
    "category": r"^[a-zA-Z0-9]+$",  # Regex pattern for category
    "page": r"^\d+$",             # Regex pattern for page number (optional)
}

query_params = urllib.parse.parse_qs(result.query)
for param, value_list in query_params.items():
    if param not in ALLOWED_QUERY_PARAMS:
        logging.error(f"Disallowed query parameter: {param}")
        return False
    pattern = ALLOWED_QUERY_PARAMS[param]
    for value in value_list:  # Handle multiple values for the same parameter
        if not re.match(pattern, value):
            logging.error(f"Invalid value for query parameter {param}: {value}")
            return False

# Clarified Sanitization Comment (in get_redirect_url)
# No sanitization is performed here.  Output encoding *MUST* be performed at the point of use to prevent XSS attacks.

