import logging
from typing import List, Optional
from ipaddress import ip_address, AddressValueError  # For IP validation

# Assume 'request' is a Flask request object (or similar)
# from flask import request  # Example for Flask

# Configure logging (if not already configured)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define a maximum length for the X-Forwarded-For header
MAX_X_FORWARDED_FOR_LENGTH = 2048  # Adjust as needed

# Define a maximum number of IPs to check in X-Forwarded-For
MAX_IPS_TO_CHECK = 5

# Define trusted proxies (replace with your actual trusted proxies)
TRUSTED_PROXIES: List[str] = ["192.168.1.1", "10.0.0.0/24"]  # Example: Single IP and CIDR range


def is_trusted_proxy(ip_address_str: str) -> bool:
    """
    Checks if an IP address is within the list of trusted proxies.
    """
    try:
        ip = ip_address(ip_address_str)
        for trusted_proxy in TRUSTED_PROXIES:
            # Handle both single IPs and CIDR ranges
            if "/" in trusted_proxy:
                # Check if the IP is within the CIDR range
                from ipaddress import ip_network
                if ip in ip_network(trusted_proxy, strict=False):  # strict=False allows network address
                    return True
            else:
                # Check if the IP matches the trusted proxy exactly
                if str(ip) == trusted_proxy:
                    return True
        return False
    except ValueError:
        logger.warning(f"Invalid IP address: {ip_address_str}")
        return False


def get_client_ip() -> Optional[str]:
    """
    Safely retrieves the client IP address, considering X-Forwarded-For and trusted proxies.
    Returns None if no valid IP can be determined.
    """
    x_forwarded_for = request.headers.get('X-Forwarded-For')

    if x_forwarded_for:
        if len(x_forwarded_for) > MAX_X_FORWARDED_FOR_LENGTH:
            logger.warning(f"X-Forwarded-For header exceeds maximum length ({MAX_X_FORWARDED_FOR_LENGTH}).  Rejecting.")
            return None  # Or handle the error appropriately

        forwarded_ips = x_forwarded_for.split(',')
        forwarded_ips = [ip.strip() for ip in forwarded_ips]

        logger.debug(f"X-Forwarded-For header: {forwarded_ips}, Remote addr: {request.remote_addr}")  # Log for debugging

        # Limit the number of IPs to check to prevent DoS
        forwarded_ips = forwarded_ips[-MAX_IPS_TO_CHECK:]  # Check last few IPs

        for ip in reversed(forwarded_ips):
            try:
                ip_address(ip)  # Validate IP address format
            except AddressValueError:
                logger.warning(f"Invalid IP address format in X-Forwarded-For: {ip}")
                continue  # Skip invalid IP addresses

            if is_trusted_proxy(request.remote_addr):
                logger.debug(f"Skipping trusted proxy IP: {ip}")
                continue
            else:
                logger.info(f"Client IP identified as: {ip} (from X-Forwarded-For)")
                return ip
    elif 'X-Real-IP' in request.headers:
        # Use X-Real-IP if available and TRUSTED_PROXIES is properly configured
        real_ip = request.headers.get('X-Real-IP')
        try:
            ip_address(real_ip) # Validate IP address format
        except AddressValueError:
            logger.warning(f"Invalid IP address format in X-Real-IP: {real_ip}")
            real_ip = None # Treat as invalid

        if real_ip and is_trusted_proxy(request.remote_addr):
            logger.info(f"Client IP identified as: {real_ip} (from X-Real-IP)")
            return real_ip
        else:
            logger.warning("X-Real-IP found, but request.remote_addr is not in TRUSTED_PROXIES or X-Real-IP is invalid.  Ignoring X-Real-IP.")
            # Fallback to request.remote_addr or return None

    logger.info(f"Client IP identified as: {request.remote_addr} (from request.remote_addr)")
    return request.remote_addr

