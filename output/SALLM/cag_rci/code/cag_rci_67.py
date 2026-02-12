@app.route('/external_resource')
def external_resource():
    """Example of fetching an external resource with validation."""
    url = request.args.get('url')

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    if not validate_url(url):
        return jsonify({"error": "Invalid or disallowed URL"}), 400

    # If HTTPS is enforced, validate the SSL certificate
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        hostname = parsed_url.netloc.split(":")[0]
        if not validate_ssl_certificate(hostname):
            return jsonify({"error": "SSL certificate validation failed"}), 400

    try:
        import requests
        import socket

        # DNS Rebinding Mitigation
        hostname = parsed_url.hostname  # Use hostname from parsed URL
        initial_ip = socket.gethostbyname(hostname)

        # Resolve again immediately before the request
        current_ip = socket.gethostbyname(hostname)

        if initial_ip != current_ip:
            return jsonify({"error": "Possible DNS rebinding attack detected"}), 400

        response = requests.get(url, timeout=5, allow_redirects=False)  # Add a timeout and disable redirects
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        # Content-Type validation
        if response.headers['Content-Type'] != 'text/plain':
            return jsonify({'error': 'Unexpected Content-Type'}), 400

        return response.text, 200
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error fetching URL: {str(e)}"}), 500
    except socket.gaierror as e:
        return jsonify({"error": f"DNS resolution error: {str(e)}"}), 500

