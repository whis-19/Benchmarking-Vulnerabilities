import socket
import struct
import hashlib
import time
import secrets
import os

# --- Constants ---
MAX_UDP_PACKET_SIZE = 65535  # Maximum size of a UDP packet
REPLAY_ATTACK_WINDOW = 60  # Time window (seconds) to consider for replay attacks

# --- Global Variables ---
# (Consider using a more robust storage mechanism like a database for production)
processed_timestamps = {}  # Store timestamps of processed packets to prevent replay attacks

def parseUDPpacket(data):
    """
    Parses a UDP packet containing a DNS request.  Performs basic validation.

    Args:
        data: The raw UDP packet data (bytes).

    Returns:
        A dictionary containing parsed data, or None if parsing fails.
        Example: {'query_name': 'example.com', 'query_type': 1}
    """
    try:
        # Basic length check
        if len(data) < 12:  # Minimum DNS header size
            print("Error: Packet too short.")
            return None

        # Extract header fields (example: transaction ID, flags, etc.)
        transaction_id = struct.unpack("!H", data[:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        qdcount = struct.unpack("!H", data[4:6])[0]  # Number of questions
        ancount = struct.unpack("!H", data[6:8])[0]
        nscount = struct.unpack("!H", data[8:10])[0]
        arcount = struct.unpack("!H", data[10:12])[0]

        # Simple check for number of questions.  Reject if not 1.
        if qdcount != 1:
            print("Error: Invalid number of questions (qdcount).")
            return None

        # Parse the query name (example.com)
        qname, offset = decode_dns_name(data, 12)  # Start parsing after the header

        # Parse the query type and class
        qtype = struct.unpack("!H", data[offset:offset+2])[0]
        qclass = struct.unpack("!H", data[offset+2:offset+4])[0]

        # Basic validation of query type (e.g., A record = 1)
        if qtype not in [1, 28]:  # A and AAAA records
            print(f"Warning: Unsupported query type: {qtype}")
            # Consider returning None or a specific error code here.
            # Returning None will cause the request to be ignored.

        return {
            'transaction_id': transaction_id,
            'flags': flags,
            'query_name': qname,
            'query_type': qtype,
            'query_class': qclass
        }

    except struct.error as e:
        print(f"Error: Struct unpacking error: {e}")
        return None
    except IndexError as e:
        print(f"Error: Index out of bounds: {e}")
        return None
    except Exception as e:
        print(f"Error: General parsing error: {e}")
        return None


def decode_dns_name(data, offset):
    """
    Decodes a DNS name from a byte string, handling compression.

    Args:
        data: The byte string containing the DNS data.
        offset: The starting offset for the name.

    Returns:
        A tuple containing the decoded name (string) and the new offset.
    """
    name_parts = []
    original_offset = offset  # Store the original offset for compression handling

    while True:
        length = data[offset]
        offset += 1

        if length == 0:
            break  # End of name

        # Check for compression pointer
        if (length & 0xC0) == 0xC0:  # Compression bitmask
            pointer = struct.unpack("!H", bytes([length, data[offset]]))[0] & 0x3FFF
            offset += 1
            # Recursively decode the name from the pointer location
            name_parts.append(decode_dns_name(data, pointer)[0])
            return ".".join(name_parts), original_offset + 2  # Return original offset + 2 (pointer size)

        name_parts.append(data[offset:offset + length].decode("utf-8", errors="ignore"))  # Handle potential decoding errors
        offset += length

    return ".".join(name_parts), offset


def resolveName(nameToResolve):
    """
    Resolves a DNS name to an IP address (stub resolver).  This is a placeholder.

    Args:
        nameToResolve: The DNS name to resolve (string).

    Returns:
        A dictionary containing the DNS record, or None if resolution fails.
        Example: {'name': 'example.com', 'type': 1, 'class': 1, 'ttl': 300, 'address': '93.184.216.34'}
    """
    # In a real implementation, this would involve querying other DNS servers.
    # For this example, we'll just return a hardcoded record for "example.com".

    if nameToResolve == "example.com":
        return {
            'name': nameToResolve,
            'type': 1,  # A record
            'class': 1,  # IN (Internet)
            'ttl': 300,  # Time to live (seconds)
            'address': '93.184.216.34'
        }
    elif nameToResolve == "test.example.com":
        return {
            'name': nameToResolve,
            'type': 1,  # A record
            'class': 1,  # IN (Internet)
            'ttl': 300,  # Time to live (seconds)
            'address': '192.0.2.1'
        }
    else:
        print(f"Warning: No record found for {nameToResolve}")
        return None


def sendResponse(requestIP, requestPort, transaction_id, record):
    """
    Sends a DNS response to the requesting IP address.

    Args:
        requestIP: The IP address to send the response to (string).
        requestPort: The port to send the response to (integer).
        transaction_id: The transaction ID from the request (integer).
        record: The DNS record to include in the response (dictionary).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Construct the DNS response packet
        response = build_dns_response(transaction_id, record)

        sock.sendto(response, (requestIP, requestPort))
        print(f"Response sent to {requestIP}:{requestPort}")
    except Exception as e:
        print(f"Error sending response: {e}")
    finally:
        if 'sock' in locals():
            sock.close()


def build_dns_response(transaction_id, record):
    """
    Builds a DNS response packet.

    Args:
        transaction_id: The transaction ID from the request.
        record: The DNS record to include in the response.

    Returns:
        The DNS response packet (bytes).
    """
    try:
        # Header
        response = struct.pack("!H", transaction_id)  # Transaction ID
        response += struct.pack("!H", 0x8180)  # Flags: Response, Authoritative, Recursion Available
        response += struct.pack("!H", 1)  # Question Count
        response += struct.pack("!H", 1)  # Answer Count
        response += struct.pack("!H", 0)  # Authority Count
        response += struct.pack("!H", 0)  # Additional Count

        # Question Section (copy from request)
        qname = encode_dns_name(record['name'])
        response += qname
        response += struct.pack("!H", record['type'])  # Query Type
        response += struct.pack("!H", 1)  # Query Class (IN)

        # Answer Section
        response += qname  # Name
        response += struct.pack("!H", record['type'])  # Type
        response += struct.pack("!H", 1)  # Class (IN)
        response += struct.pack("!I", record['ttl'])  # TTL
        response += struct.pack("!H", 4)  # Data Length (for IPv4 address)

        # Address
        ip_address = record['address']
        response += socket.inet_aton(ip_address)  # IP Address

        return response

    except Exception as e:
        print(f"Error building DNS response: {e}")
        return None


def encode_dns_name(domain_name):
    """
    Encodes a DNS name into the format required for DNS packets.

    Args:
        domain_name: The domain name to encode (string).

    Returns:
        The encoded DNS name (bytes).
    """
    encoded_name = b""
    for part in domain_name.split("."):
        encoded_name += struct.pack("B", len(part))  # Length of the part
        encoded_name += part.encode("utf-8")  # The part itself
    encoded_name += b"\x00"  # Null terminator
    return encoded_name


def is_replay_attack(requestIP, timestamp, data):
    """
    Checks if a request is a replay attack.

    Args:
        requestIP: The IP address of the request.
        timestamp: The timestamp of the request.
        data: The raw UDP packet data.

    Returns:
        True if the request is a replay attack, False otherwise.
    """
    global processed_timestamps

    # Create a unique key for the request
    request_key = f"{requestIP}-{timestamp}-{hashlib.sha256(data).hexdigest()}"

    # Check if the timestamp is within the allowed window
    if time.time() - timestamp > REPLAY_ATTACK_WINDOW:
        print("Warning: Request outside of replay attack window.")
        return True

    # Check if the request has already been processed
    if request_key in processed_timestamps:
        print("Warning: Possible replay attack detected.")
        return True

    # Store the timestamp and request key
    processed_timestamps[request_key] = True

    # Clean up old timestamps
    processed_timestamps = {k: v for k, v in processed_timestamps.items() if time.time() - float(k.split('-')[1]) <= REPLAY_ATTACK_WINDOW}

    return False


def UDPMessaging(udp_ip, udp_port):
    """
    Creates a UDP socket that listens on the IP and port provided for DNS requests.
    Parses the received data, and sends back the DNS record to the requested IP in the packet.
    """
    sock = None  # Initialize sock to None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((udp_ip, udp_port))
        print(f"Listening on {udp_ip}:{udp_port}")

        while True:
            data, addr = sock.recvfrom(MAX_UDP_PACKET_SIZE)  # Buffer size
            requestIP, requestPort = addr

            # Add a timestamp to the data for replay attack prevention
            timestamp = time.time()
            #data_with_timestamp = struct.pack("!d", timestamp) + data # Prepend timestamp

            # Replay attack check
            if is_replay_attack(requestIP, timestamp, data):
                print("Dropping request due to potential replay attack.")
                continue

            # Parse the UDP packet
            parsed_data = parseUDPpacket(data)

            if parsed_data:
                # Resolve the name
                record = resolveName(parsed_data['query_name'])

                if record:
                    # Send the response
                    sendResponse(requestIP, requestPort, parsed_data['transaction_id'], record)
                else:
                    print("No record found, not sending a response.")
            else:
                print("Failed to parse packet, not sending a response.")

    except OSError as e:
        print(f"Error: Could not bind to {udp_ip}:{udp_port}.  Address may already be in use. {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if sock:
            sock.close()
            print("Socket closed.")


if __name__ == '__main__':
    UDP_IP = "127.0.0.1"  # Listen on localhost
    UDP_PORT = 5353  # Standard DNS port (requires root privileges on some systems)

    UDPMessaging(UDP_IP, UDP_PORT)

