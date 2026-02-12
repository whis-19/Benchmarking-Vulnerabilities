import http.server
import socketserver
import io
import cgi
import html
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def http_hello_page(request, response):
    """
    Handles an HTTP request to greet a user by name.

    Args:
        request: A file-like object representing the HTTP request from the client.
        response: A file-like object to write the HTTP response to.
    """

    try:
        # Parse the request using cgi.FieldStorage.  This is safer than manually parsing.
        form = cgi.FieldStorage(fp=request, environ={'REQUEST_METHOD': 'POST'})  # Assuming POST request

        # Get the username from the form data.  Use getfirst() to handle multiple values safely.
        username = form.getfirst("username")

        if username:
            # Sanitize the username to prevent XSS vulnerabilities.  Crucial!
            safe_username = html.escape(username)

            # Construct the response.
            greeting = f"Hello {safe_username}"
            html_response = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Greeting</title>
            </head>
            <body>
                <h1>{greeting}</h1>
            </body>
            </html>
            """

            # Write the HTTP response headers.  Important for proper communication.
            response.write("HTTP/1.1 200 OK\r\n")
            response.write("Content-Type: text/html\r\n")
            response.write("\r\n")  # End of headers

            # Write the HTML response body.
            response.write(html_response.encode("utf-8"))  # Encode to bytes

        else:
            # Handle the case where the username is missing.  Return an error.
            error_message = "Error: Username is required."
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error</title>
            </head>
            <body>
                <h1>{error_message}</h1>
            </body>
            </html>
            """
            response.write("HTTP/1.1 400 Bad Request\r\n")
            response.write("Content-Type: text/html\r\n")
            response.write("\r\n")
            response.write(error_html.encode("utf-8"))

    except Exception as e:
        # Handle any exceptions that occur during processing.  Log the error.
        logging.exception("An error occurred while processing the request:")
        error_message = f"Internal Server Error: {e}"
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error</title>
        </head>
        <body>
            <h1>{error_message}</h1>
        </body>
        </html>
        """
        response.write("HTTP/1.1 500 Internal Server Error\r\n")
        response.write("Content-Type: text/html\r\n")
        response.write("\r\n")
        response.write(error_html.encode("utf-8"))


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/hello':
            # Read the request body
            content_length = int(self.headers['Content-Length'])
            request_body = self.rfile.read(content_length)
            request_stream = io.BytesIO(request_body)

            # Create a response stream
            response_stream = io.BytesIO()

            # Call the handler function
            http_hello_page(request_stream, response_stream)

            # Send the response back to the client
            response_stream.seek(0)
            response_body = response_stream.read()

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(response_body)
        else:
            super().do_GET()  # Handle other requests normally

# Set up the server
PORT = 8000
Handler = MyHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()

