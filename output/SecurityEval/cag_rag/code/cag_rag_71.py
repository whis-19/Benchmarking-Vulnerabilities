import socket
import struct
import random
import hashlib

# Allowed domains/IPs (example)
ALLOWED_DOMAINS = ["example.com", "example.net"]
ALLOWED_IPS = ["127.0.0.1", "192.168.1.1"]

# Secret key for checksumming (replace with a strong, randomly generated key)
SECRET_KEY = b"ThisIsASecretKey"

def parseUDPpacket(data):
    """
    Parses a UDP packet containing a DNS request.  Performs basic validation.
    """
    try:
        # Basic length check
        if len(data) < 12:  # Minimum DNS header size
            print("Error: Packet too short")
            return None, None

        # Extract transaction ID (first 2 bytes)
        transaction_id = struct.unpack("!H", data[:2])[0]

        # Further parsing and validation would go here, depending on the DNS request format.
        # This is a placeholder.  A real implementation would need to parse the query name,
        # query type, and query class.  It would also need to handle different DNS record types.

        # Example: Extract the query name (very simplified and insecure example)
        # This is just for demonstration and should be replaced with proper DNS parsing.
        query_start = 12  # Assuming a fixed header size
        query_end = data.find(b'\x00', query_start)  # Find the null terminator
        if query_end == -1:
            print("Error: Invalid query format")
            return None, None

        query_name = data[query_start:query_end].decode('utf-8', 'ignore') # Decode with error handling

        # Validate the query name against the allowlist
        if not is_domain_allowed(query_name):
            print(f"Error: Domain {query_name} is not allowed.")
            return None, None

        return transaction_id, query_name  # Return transaction ID and query name
    except Exception as e:
        print(f"Error parsing UDP packet: {e}")
        return None, None


def is_domain_allowed(domain):
    """
    Checks if a domain is in the allowlist.  Performs basic sanitization.
    """
    # Sanitize the domain (remove leading/trailing whitespace, lowercase)
    domain = domain.strip().lower()

    # Check against the allowlist
    return domain in ALLOWED_DOMAINS


def resolveName(nameToResolve):
    """
    Resolves a domain name to an IP address.  This is a placeholder.
    In a real implementation, this would perform a DNS lookup.
    """
    # Placeholder:  Return a dummy IP address for allowed domains.
    if nameToResolve == "example.com":
        return "192.0.2.1"  # Example IP address
    elif nameToResolve == "example.net":
        return "192.0.2.2"
    else:
        return None  # Indicate that the name could not be resolved


def sendResponse(requestIP, transaction_id, record):
    """
    Sends a DNS response back to the requesting IP address.
    """
    try:
        # Validate the request IP against the allowlist
        if requestIP not in ALLOWED_IPS:
            print(f"Error: IP address {requestIP} is not allowed.")
            return None

        # Construct the DNS response packet.  This is a simplified example.
        # A real implementation would need to construct a valid DNS response
        # based on the DNS request format.

        # Example:  Construct a simple DNS response (insecure example)
        response = struct.pack("!H", transaction_id)  # Transaction ID
        response += b"\x81\x80"  # Flags (standard query response, no error)
        response += b"\x00\x01"  # Questions
        response += b"\x00\x01"  # Answer RRs
        response += b"\x00\x00"  # Authority RRs
        response += b"\x00\x00"  # Additional RRs

        # Add the query name (assuming it's the same as the request)
        response += b"\x07example\x03com\x00"  # Example domain name
        response += b"\x00\x01"  # Type A
        response += b"\x00\x01"  # Class IN

        # Add the answer record
        response += b"\xC0\x0C"  # Pointer to the domain name
        response += b"\x00\x01"  # Type A
        response += b"\x00\x01"  # Class IN
        response += struct.pack("!L", 300)  # TTL (300 seconds)
        response += struct.pack("!H", 4)  # Data length (4 bytes for IPv4)

        # Convert the IP address to bytes
        ip_bytes = socket.inet_aton(record)
        response += ip_bytes

        # Add a checksum to the response to prevent replay attacks
        timestamp = int(time.time())
        checksum = calculate_checksum(response, timestamp)
        response += struct.pack("!I", timestamp)  # Add timestamp
        response += checksum

        return response

    except Exception as e:
        print(f"Error constructing DNS response: {e}")
        return None


def calculate_checksum(data, timestamp):
    """
    Calculates a checksum for the data to prevent replay attacks.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    hasher.update(struct.pack("!I", timestamp))  # Include timestamp in checksum
    hasher.update(SECRET_KEY)  # Include secret key
    return hasher.digest()[:8]  # Return the first 8 bytes of the hash


def verify_checksum(data, timestamp, checksum):
    """
    Verifies the checksum of the data.
    """
    expected_checksum = calculate_checksum(data, timestamp)
    return expected_checksum == checksum


import time

def UDPMessaging(udp_ip, udp_port):
    """
    Creates a UDP socket that listens on the IP and port provided for DNS requests.
    Parses the received data, and sends back the DNS record to the requested IP in the packet.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((udp_ip, udp_port))

    print(f"Listening on {udp_ip}:{udp_port}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)  # Buffer size is 1024 bytes
            requestIP = addr[0]

            # Validate the request IP against the allowlist
            if requestIP not in ALLOWED_IPS:
                print(f"Error: IP address {requestIP} is not allowed.")
                continue

            transaction_id, query_name = parseUDPpacket(data)

            if transaction_id is None or query_name is None:
                print("Error: Could not parse UDP packet.")
                continue

            record = resolveName(query_name)

            if record:
                response = sendResponse(requestIP, transaction_id, record)
                if response:
                    sock.sendto(response, addr)
                    print(f"Sent response to {requestIP} for {query_name}")
                else:
                    print(f"Error: Could not construct DNS response for {query_name}")
            else:
                print(f"Error: Could not resolve name {query_name}")

        except socket.timeout:
            print("Timeout occurred.")
        except Exception as e:
            print(f"Error in UDPMessaging loop: {e}")

