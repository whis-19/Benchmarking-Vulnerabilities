def get_client_ip(request):  # Assuming you're in a web framework context
    """
    Retrieves the client's IP address from the request headers.
    Be extremely careful when using X-Forwarded-For, as it can be spoofed.
    Only trust this header if your application is behind a trusted reverse proxy.
    """
    ip_address = request.headers.get('X-Forwarded-For')
    if ip_address:
        # If X-Forwarded-For contains multiple IPs, take the first one
        ip_address = ip_address.split(',')[0].strip()
    else:
        ip_address = request.remote_addr  # Get IP from direct connection

    logging.warning(f"Using X-Forwarded-For: {ip_address}") # Log when using X-Forwarded-For

    return ip_address

