import asyncio
import ssl
import logging
import argparse  # For command-line arguments
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureClientProtocol(asyncio.Protocol):
    """
    A secure client protocol that handles data received from the server
    and performs basic security checks.
    """

    def __init__(self):
        super().__init__()
        self.transport = None  # Initialize transport

    def connection_made(self, transport):
        """Called when a connection is made."""
        self.transport = transport
        peername = transport.get_extra_info('peername')
        logging.info(f"Connected to server: {peername}")

    def data_received(self, data):
        """Called when data is received from the server."""
        try:
            decoded_data = data.decode('utf-8')  # Explicit encoding
            logging.info(f"Received data: {decoded_data}")

            # **CRITICAL:  Implement robust data validation and sanitization here!**
            # This is just a placeholder.  Replace with your actual validation logic.
            if not self._is_valid_data(decoded_data):
                logging.warning("Invalid data received. Closing connection.")
                self.transport.close()
                return

            # Process the data (e.g., parse JSON, handle HTML, etc.)
            self._process_data(decoded_data)

        except UnicodeDecodeError:
            logging.error("Received non-UTF-8 encoded data.  Closing connection.")
            self.transport.close()
        except Exception as e:
            logging.exception(f"Error processing data: {e}")
            self.transport.close()

    def connection_lost(self, exc):
        """Called when the connection is lost."""
        if exc:
            logging.error(f"Connection lost due to error: {exc}")
        else:
            logging.info("Connection closed by server.")

    def _is_valid_data(self, data):
        """Placeholder for data validation logic.  MUST BE IMPLEMENTED."""
        # **IMPLEMENT THIS METHOD!**
        # Example: Check for allowed characters, maximum length, etc.
        # This is a critical security step to prevent injection attacks.
        # Replace this with your specific validation rules.
        if len(data) > 1024:  # Example: Limit data length
            return False
        return True  # Replace with your actual validation logic

    def _process_data(self, data):
        """Placeholder for data processing logic.  MUST BE IMPLEMENTED."""
        # **IMPLEMENT THIS METHOD!**
        # This is where you would parse the data, update your application state, etc.
        # Be very careful about potential security vulnerabilities here.
        logging.info(f"Processing data: {data}")
        # Example:  If you expect JSON, use json.loads() with error handling.
        # Example:  If you expect HTML, use a sanitization library like bleach.
        pass  # Replace with your actual processing logic


async def main(host, port):
    """Main function to establish a secure connection."""
    try:
        # 1. Configure SSL Context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # context.load_verify_locations('/path/to/your/ca_bundle.pem') # Optional: Specify CA bundle
        context.check_hostname = True  # Enable hostname verification
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require TLS 1.2 or higher
        # Example cipher suite (adjust as needed, consult security experts)
        context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256')

        # 2. Create Connection
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_connection(
            SecureClientProtocol,  # Use the custom protocol class
            host=host,
            port=port,
            ssl=context,
            server_hostname=host  # Use the provided hostname for SNI
        )

        # 3. Send Data (Optional - depends on your application)
        # Example: Send an HTTP request
        # request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        # protocol.transport.write(request.encode('utf-8'))

        # 4. Keep connection alive for a short time (adjust as needed)
        await asyncio.sleep(5)

        # 5. Close the connection
        transport.close()

    except Exception as e:
        logging.error(f"Connection error: {e}")


if __name__ == "__main__":
    # 6. Use argparse to handle command-line arguments
    parser = argparse.ArgumentParser(description="Secure Asynchronous Client")
    parser.add_argument("host", help="The hostname to connect to")
    parser.add_argument("-p", "--port", type=int, default=443, help="The port to connect to (default: 443)")
    args = parser.parse_args()

    # Run the main function
    try:
        asyncio.run(main(args.host, args.port))
    except KeyboardInterrupt:
        print("Client interrupted.")
        sys.exit(0)

