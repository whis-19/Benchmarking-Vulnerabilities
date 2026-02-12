# Example: Strict IP address validation during startup
import ipaddress

def validate_ip_list(ip_list):
    validated_ips = []
    for ip_str in ip_list:
        try:
            if "/" in ip_str:
                validated_ips.append(ipaddress.ip_network(ip_str, strict=False))
            else:
                validated_ips.append(ipaddress.ip_address(ip_str))
        except ValueError as e:
            raise ValueError(f"Invalid IP address or CIDR block: {ip_str}") from e
    return validated_ips

try:
    ALLOWED_IPS = validate_ip_list(os.environ.get("ALLOWED_IPS", "192.168.1.1,10.0.0.0/24").split(",").strip()) # Added .strip()
except ValueError as e:
    logging.error(f"Invalid ALLOWED_IPS configuration: {e}")
    raise  # Exit the application if the configuration is invalid

# Example: Setting session cookie attributes
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Example: SSL/TLS Cipher Suite Configuration
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('cert.pem', 'key.pem')
context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384') # Example Cipher Suite
context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 # Disable old protocols
app.run(debug=False, ssl_context=context) # Disable debug mode in production

