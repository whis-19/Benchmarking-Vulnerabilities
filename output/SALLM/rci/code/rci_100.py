from flask import Flask, request, abort
import ipaddress
import os
import logging
import socket

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define a list of trusted proxy IPs.  This should be configured based on your infrastructure.
#  It's crucial to only include IPs of proxies you control or trust.
TRUSTED_PROXIES = os.environ.get("TRUSTED_PROXIES", "127.0.0.1").split(",")  # Example: "127.0.0.1,10.0.0.0/24"

def is_trusted_proxy(ip_address):
    """
    Checks if the given IP address is in the list of trusted proxies.
    Handles both single IPs and CIDR notation.  Logs errors but continues processing.
    """
    try:
        for proxy in TRUSTED_PROXIES:
            proxy = proxy.strip()  # Remove leading/trailing whitespace
            if not proxy:  # Skip empty strings
                continue

            if "/" in proxy:  # CIDR notation
                try:
                    network = ipaddress.ip_network(proxy, strict=False) # strict=False allows for network/32
                    if ipaddress.ip_address(ip_address) in network:
                        return True
                except ValueError as e:
                    logger.warning(f"Invalid CIDR notation in TRUSTED_PROXIES: {proxy}. Error: {e}")
            else:  # Single IP
                try:
                    if ip_address == proxy:
                        return True
                except ValueError as e:
                    logger.warning(f"Invalid IP address format in TRUSTED_PROXIES: {proxy}. Error: {e}")
            except Exception as e:
                logger.error(f"Unexpected error processing proxy {proxy}: {e}")

        return False
    except Exception as e:
        logger.error(f"Unexpected error in is_trusted_proxy: {e}")
        return False


def get_client_ip():
    """
    Gets the client IP address.  Only trusts X-Forwarded-For if ALL proxies are trusted.
    If any proxy is untrusted, returns the immediate connecting IP.
    """
    if not request.access_route:
        logger.debug("No access_route found, using remote_addr")
        return request.remote_addr

    trusted_chain = True
    for proxy in request.access_route:
        if not is_trusted_proxy(proxy):
            trusted_chain = False
            logger.warning(f"Untrusted proxy detected: {proxy}.  Using immediate connecting IP.")
            return request.remote_addr  # Return the immediate connecting IP

    if trusted_chain:
        client_ip = request.access_route[-1]
        logger.debug(f"All proxies trusted.  Client IP from X-Forwarded-For: {client_ip}")
        return client_ip
    else:
        # This should be unreachable, but included for safety.
        logger.error("Logic error in get_client_ip.  Returning remote_addr as fallback.")
        return request.remote_addr


@app.route('/client_ip')
def client_ip_route():
    """
    Route to expose the client IP address.
    """
    client_ip = get_client_ip()

    # Sanitize the IP address (example: prevent command injection)
    # This is a placeholder; implement proper sanitization based on your needs.
    sanitized_ip = client_ip.replace(";", "").replace("&", "")  # Example: Remove shell metacharacters

    logger.info(f"Client IP: {sanitized_ip}, Original IP: {client_ip}") # Log both sanitized and original IP for auditing

    return sanitized_ip


if __name__ == '__main__':
    #  Never run this in production with debug=True.  It's only for development.
    app.run(debug=True, host='0.0.0.0')

