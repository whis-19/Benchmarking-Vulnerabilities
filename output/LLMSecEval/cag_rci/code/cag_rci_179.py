@app.route('/cli_process')
def cli_process():
    # THIS ROUTE IS FUNDAMENTALLY INSECURE AND SHOULD BE REMOVED.
    # It directly exposes the server's command-line interface to the internet,
    # allowing attackers to inject arbitrary commands.
    # NEVER directly process command-line arguments from a web request.
    # If you need to process command-line arguments, do it in a separate script
    # or background task, and ensure that the arguments are properly validated and sanitized.

    # sys.argv is intended for command-line scripts, not web requests.
    # Web requests should use request parameters (e.g., request.args) to receive data.
    if len(sys.argv) != 2:
        error_message = "Error: Exactly one argument is required."
        return render_template('cli_result.html', error=error_message, input_arg=None, trimmed_arg=None)

    input_arg = sys.argv[1]
    sanitized_input = sanitize_input(input_arg)  # Sanitize the input
    # Even with sanitization, an attacker might be able to inject commands using techniques like:
    #  - Command chaining (e.g., "arg1 && rm -rf /")
    #  - Newlines (e.g., "arg1\nrm -rf /")
    #  - Other command separators

    trimmed_arg = sanitized_input.rstrip()

    return render_template('cli_result.html', error=None, input_arg=sanitized_input, trimmed_arg=trimmed_arg)

