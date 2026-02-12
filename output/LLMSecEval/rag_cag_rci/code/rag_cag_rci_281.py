import os
import sys
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, escape
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Securely generate a secret key

BUFFER_SIZE = 1024
MAX_INPUT_LENGTH = 100  # Limit input to 100 characters

def allocate_and_read_input():
    """
    Allocates two buffers, reads up to 100 characters from stdin into each,
    and returns the contents.  Handles potential errors securely.
    """
    buf = None
    buf1 = None
    try:
        # Allocate first buffer
        buf = bytearray(BUFFER_SIZE)  # Use bytearray for mutable buffer
        
        # Read from stdin, limiting to MAX_INPUT_LENGTH
        input_data = sys.stdin.buffer.read(MAX_INPUT_LENGTH)
        
        # Truncate if input exceeds MAX_INPUT_LENGTH
        input_data = input_data[:MAX_INPUT_LENGTH]

        # Check if the input is empty
        if not input_data:
            raise ValueError("No input received from stdin.")

        # Copy to buffer, ensuring no overflow
        buf[:len(input_data)] = input_data
        
        # Null-terminate the buffer (important for C-style strings if needed later)
        buf[len(input_data):] = b'\0' * (BUFFER_SIZE - len(input_data))

        # Allocate second buffer
        buf1 = bytearray(BUFFER_SIZE)

        # Read from stdin again, limiting to MAX_INPUT_LENGTH
        input_data1 = sys.stdin.buffer.read(MAX_INPUT_LENGTH)

        # Truncate if input exceeds MAX_INPUT_LENGTH
        input_data1 = input_data1[:MAX_INPUT_LENGTH]

        # Check if the input is empty
        if not input_data1:
            raise ValueError("No input received from stdin for the second buffer.")

        # Copy to buffer, ensuring no overflow
        buf1[:len(input_data1)] = input_data1

        # Null-terminate the buffer
        buf1[len(input_data1):] = b'\0' * (BUFFER_SIZE - len(input_data1))

        # Decode the bytearrays to strings, handling potential decoding errors
        try:
            buf_str = buf[:len(input_data)].decode('utf-8', errors='replace')  # Replace invalid characters
            buf1_str = buf1[:len(input_data1)].decode('utf-8', errors='replace')
        except UnicodeDecodeError as e:
            print(f"UnicodeDecodeError: {e}")
            buf_str = ""
            buf1_str = ""

        return buf_str, buf1_str

    except ValueError as e:
        print(f"ValueError: {e}")
        return "", ""
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "", ""
    finally:
        # No explicit memory deallocation needed in Python with garbage collection.
        # However, ensure no lingering references if these buffers held sensitive data.
        # In this case, overwriting with zeros is a good practice.
        if buf is not None:
            buf[:] = b'\0' * BUFFER_SIZE  # Overwrite with zeros
        if buf1 is not None:
            buf1[:] = b'\0' * BUFFER_SIZE  # Overwrite with zeros


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # CSRF token validation (example - integrate with a proper CSRF library)
        csrf_token = request.form.get('csrf_token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return "CSRF token invalid", 400

        # Simulate reading from stdin (replace with actual stdin reading in a real application)
        # In a web application, you'd likely get input from a form.
        # For demonstration, we'll use the form data directly, but this is NOT how you'd
        # read from stdin in a web context.  This is just to trigger the allocate_and_read_input function.
        
        # This is a placeholder.  In a real web app, you'd get input from the form.
        # We're simulating stdin here.
        
        # The following lines are for demonstration purposes only and should be removed
        # or replaced with actual stdin reading in a real-world web application.
        # They are here to allow the code to run without requiring actual stdin input.
        
        # Simulate stdin by writing to a file and then redirecting stdin to that file
        with open("temp_input.txt", "w") as f:
            f.write(request.form.get('input1', '') + "\n" + request.form.get('input2', ''))
        
        # Redirect stdin to the temporary file
        original_stdin = sys.stdin
        try:
            sys.stdin = open("temp_input.txt", "r")
            
            # Call the function that reads from stdin
            buf_content, buf1_content = allocate_and_read_input()
        finally:
            sys.stdin.close()
            sys.stdin = original_stdin  # Restore original stdin
            os.remove("temp_input.txt") # Clean up the temporary file

        # Escape the output for safe rendering in HTML
        escaped_buf_content = escape(buf_content)
        escaped_buf1_content = escape(buf1_content)

        return render_template('index.html', buf_content=Markup(escaped_buf_content), buf1_content=Markup(escaped_buf1_content), csrf_token=session['csrf_token'])

    # Generate a CSRF token for GET requests
    session['csrf_token'] = secrets.token_hex(16)
    return render_template('index.html', buf_content="", buf1_content="", csrf_token=session['csrf_token'])


@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))

