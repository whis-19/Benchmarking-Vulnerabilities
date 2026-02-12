import shlex  # Import shlex

# ... (rest of the code)

    try:
        # Use subprocess.run with argument list and timeout for safety
        hostname = urlparse(url).netloc
        result = subprocess.run(['/bin/ping', '-c', '3', hostname],  # Ping by hostname only, using full path
                                capture_output=True,
                                text=True,
                                timeout=10,  # Timeout after 10 seconds
                                check=False)  # Do not raise exception on non-zero exit code.  check=False prevents an exception if ping fails (non-zero exit code).

        pong = result.stdout
        return render_template_string('''
            <p>Ping Result:</p>
            <pre>{{ pong }}</pre>
            <a href="/ping_form">Back to Ping Form</a>
        ''', pong=pong)

    except subprocess.TimeoutExpired:
        return "Error: Ping command timed out."
    except Exception as e:
        app.logger.exception("An error occurred during ping:") # Log the full exception
        # Provide a more user-friendly error message without revealing sensitive details
        return "Error: An error occurred while pinging the server. Please try again later."

# ... (rest of the code)

# Example where shlex.quote would be useful (but not in this specific ping example)
# command = f"some_command {shlex.quote(user_provided_string)}"

# Consider using Flask-Talisman for CSP nonces/hashes and HTTPS enforcement.

