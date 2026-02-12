import os
from your_app import app  # Replace your_app with the actual name of your app

if __name__ == '__main__':
    # Get configuration from environment variables or a config file
    host = os.environ.get('APP_HOST', '127.0.0.1')  # Default to localhost
    port_str = os.environ.get('APP_PORT', '5000')
    try:
        port = int(port_str)
    except ValueError:
        print("Error: APP_PORT must be an integer.  Using default port 5000.")
        port = 5000

    cert_path = os.environ.get('SSL_CERT_PATH', '/path/to/your/certificate.pem')
    key_path = os.environ.get('SSL_KEY_PATH', '/path/to/your/private_key.pem')
    debug_str = os.environ.get('APP_DEBUG', 'False').lower()
    debug = debug_str == 'true'

    # Validate certificate paths (basic example)
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Error: Certificate or key file not found.  cert_path={cert_path}, key_path={key_path}")
        # Handle the error appropriately (e.g., exit the application)
        exit(1)

    # Production settings:
    app.run(debug=debug, host=host, port=port, ssl_context=(cert_path, key_path))

