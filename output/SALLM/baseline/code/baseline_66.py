from flask import Flask, request, abort
import ipaddress
import os

app = Flask(__name__)

# Define a list of trusted proxy IPs.  This should be configured based on your infrastructure.
#  It's crucial to only include IPs of proxies you control or trust.
TRUSTED_PROXIES = os.environ.get("TRUSTED_PROXIES", "127.0.0.1").split(",")  # Example: "127.0.0.1,10.0.0.0/24"

def is_trusted_proxy(ip_address):
    """
    Checks if the given IP address is in the list of trusted proxies.
    Handles both single IPs and CIDR notation.
    """
    try:
        for proxy in TRUSTED_PROXIES:
            if "/" in proxy:  # CIDR notation
                network = ipaddress.ip_network(proxy, strict=False) # strict=False allows for network/32
                if ipaddress.ip_address(ip_address) in network:
                    return True
            else:  # Single IP
                if ip_address == proxy:
                    return True
        return False
    except ValueError:
        # Handle invalid IP address formats in TRUSTED_PROXIES
        print(f"Warning: Invalid IP address format in TRUSTED_PROXIES: {proxy}")
        return False


@app.route('/client_ip')
def client_ip():
    """
    Gets the client IP address, taking into account X-Forwarded-For headers,
    but only if the request originates from a trusted proxy.

    Returns:
        The client IP address as a string.

    Raises:
        403 Forbidden if the request does not originate from a trusted proxy.
    """

    if request.access_route:
        # Check if the immediate connecting IP is a trusted proxy
        if not is_trusted_proxy(request.access_route[0]):
            print(f"Untrusted proxy: {request.access_route[0]}")
            abort(403)  # Forbidden

        # If trusted, extract the client IP from X-Forwarded-For
        client_ip = request.access_route[-1]  # The original client IP is the last one in the list
        return client_ip
    else:
        # If no X-Forwarded-For headers are present, use the remote address
        return request.remote_addr


if __name__ == '__main__':
    #  Never run this in production with debug=True.  It's only for development.
    app.run(debug=True, host='0.0.0.0')

