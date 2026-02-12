from flask import Flask, request, abort
import ipaddress
import os

app = Flask(__name__)

# Define a list of trusted proxy IPs.  This should be configured based on your infrastructure.
#  For example, if you are behind a load balancer with a known IP, add it here.
TRUSTED_PROXIES = os.environ.get("TRUSTED_PROXIES", "").split(",")  # Read from environment variable for flexibility

def is_trusted_proxy(ip_address):
    """
    Checks if the given IP address is in the list of trusted proxies.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        for proxy in TRUSTED_PROXIES:
            if proxy.strip() == "":  # Handle empty strings in the list
                continue
            if ipaddress.ip_address(proxy.strip()) == ip:
                return True
        return False
    except ValueError:
        return False  # Invalid IP address format

def get_client_ip():
    """
    Safely retrieves the client IP address, considering X-Forwarded-For headers
    and trusted proxies.
    """
    if 'X-Forwarded-For' in request.headers:
        forwarded_for = request.headers.getlist("X-Forwarded-For")
        # Iterate through the IPs in reverse order, starting from the client's IP.
        for ip in reversed(forwarded_for):
            ip = ip.strip()
            if not is_trusted_proxy(ip):
                return ip  # Return the first non-trusted IP as the client IP
        # If all IPs in X-Forwarded-For are trusted proxies, fall back to the remote_addr.
        # This is a safety net, but ideally, you should configure your proxies correctly.
        return request.remote_addr
    else:
        return request.remote_addr  # If no X-Forwarded-For header, use remote_addr

@app.route('/client_ip')
def client_ip():
    """
    Returns the client IP address.  This version is secure against IP spoofing.
    """
    client_ip_address = get_client_ip()

    # Example: Check if the client IP is a local IP (optional security check)
    try:
        ip = ipaddress.ip_address(client_ip_address)
        if ip.is_private:
            # Log the attempt and potentially take other actions.  Don't just raise an exception.
            print(f"WARNING: Local IP address detected: {client_ip_address}")
            abort(403)  # Forbidden - Access denied
    except ValueError:
        # Handle invalid IP address format (e.g., if remote_addr is not an IP)
        print(f"WARNING: Invalid IP address format: {client_ip_address}")
        abort(400)  # Bad Request

    return f"Client IP: {client_ip_address}"


if __name__ == '__main__':
    #  Never run in production with debug=True.  This is for development only.
    app.run(debug=True, host='0.0.0.0', port=5000)

