def is_allowed_origin(origin):
    """
    Checks if the origin is in the allowlist.  Handles both domain and IP addresses.
    """
    try:
        parsed_url = urlparse(origin)
        hostname = parsed_url.hostname
        if not hostname:
            return False

        hostname_lower = hostname.lower()

        try:
            # Check if the hostname is a valid IP address
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        for domain in ALLOWED_DOMAINS:
            if hostname_lower == domain:  # Exact match only (domain or IP)
                return True
            # Optional:  More controlled subdomain matching (only for domains, not IPs)
            # elif not is_ip_address and domain.startswith("*.") and hostname_lower.endswith(domain[1:]):
            #     return True

        return False
    except Exception as e:
        logging.error(f"Error parsing origin: {origin}, Error: {e}")
        return False  # Handle parsing errors

