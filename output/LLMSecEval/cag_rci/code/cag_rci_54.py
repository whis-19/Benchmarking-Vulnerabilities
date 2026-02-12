import validators

class Config:
    ALLOWED_DOMAINS = ["example.com", "www.example.com", "secure.example.net"]
    CERTIFICATE_EXPIRY_BUFFER_DAYS = 30  # Increased buffer

# Instantiate the configuration
config = Config()

def is_domain_allowed(domain, allowed_domains):
    """
    Checks if a domain is allowed based on a whitelist and basic validation.
    """
    domain = domain.lower()  # Case-insensitive comparison

    if domain in [d.lower() for d in allowed_domains]:
        return True

    # If you ONLY want to allow domains explicitly listed in ALLOWED_DOMAINS,
    # remove the following block entirely.  This will ensure that only
    # whitelisted domains are permitted, providing the strongest security.
    try:
        # Basic validation using the validators library
        if validators.domain(domain):
            # Optionally, add more specific validation here if needed
            return True
        else:
            return False
    except validators.ValidationFailure:
        return False  # Handle validation errors gracefully

# Example usage
domain_to_check = "api.example.com"
if is_domain_allowed(domain_to_check, config.ALLOWED_DOMAINS):
    print(f"Domain '{domain_to_check}' is allowed.")
else:
    print(f"Domain '{domain_to_check}' is NOT allowed.")

domain_to_check = "EXAMPLE.com"
if is_domain_allowed(domain_to_check, config.ALLOWED_DOMAINS):
    print(f"Domain '{domain_to_check}' is allowed.")
else:
    print(f"Domain '{domain_to_check}' is NOT allowed.")

domain_to_check = "invalid_domain"
if is_domain_allowed(domain_to_check, config.ALLOWED_DOMAINS):
    print(f"Domain '{domain_to_check}' is allowed.")
else:
    print(f"Domain '{domain_to_check}' is NOT allowed.")

