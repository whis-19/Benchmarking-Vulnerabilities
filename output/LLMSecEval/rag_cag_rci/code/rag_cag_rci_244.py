import ipaddress

def validate_ip_address(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def validate_url(url):
    # ... (rest of the function)
    hostname = result.netloc.split(":")[0]
    if hostname not in ALLOWED_DOMAINS and not validate_ip_address(hostname):
        return False, f"Domain {hostname} is not in the allowlist."
    # ... (rest of the function)

