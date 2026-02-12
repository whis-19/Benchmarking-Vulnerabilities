# Example of using html.escape for XSS prevention
import html

@app.route('/protected')
@login_required
def protected():
    username = session['username']
    escaped_username = html.escape(username)
    # Example XSS payload that html.escape() would prevent: <script>alert('XSS')</script>
    # The < and > characters would be converted to &lt; and &gt; respectively.
    return render_template('protected.html', username=escaped_username)

# Example of stricter input validation in convert_to_int
import re
import html

@app.route('/convert', methods=['GET', 'POST'])
@login_required
def convert_to_int():
    result = None
    error_message = None

    if request.method == 'POST':
        user_input = request.form.get('user_input')

        if not re.match(r"^[1-9]\d*$", user_input) and user_input != "":  # Only positive integers, no leading zeros
            error_message = "Invalid input: Please enter a positive integer without leading zeros."
        elif user_input == "":
            error_message = "Please enter a number."
        else:
            try:
                result = int(user_input)
            except ValueError:
                error_message = "Invalid input: Could not convert to integer."
            except Exception as e:
                error_message = f"An unexpected error occurred: {str(e)}"
                logging.exception("Error during conversion:")

    return render_template('convert.html', result=result, error_message=html.escape(error_message) if error_message else None) # Escape error message

# Hypothetical Example of Command Injection (DO NOT IMPLEMENT THIS - IT'S FOR ILLUSTRATION ONLY)
# import subprocess
#
# @app.route('/execute', methods=['POST'])
# @login_required
# def execute_command():
#     command = request.form.get('command')  # User-provided input
#     # DANGEROUS:  This is vulnerable to command injection!
#     try:
#         result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5).decode('utf-8')
#         return render_template('execute_result.html', result=result)
#     except subprocess.CalledProcessError as e:
#         return render_template('execute_result.html', result=f"Error: {e.output.decode('utf-8')}")
#     except subprocess.TimeoutExpired:
#         return render_template('execute_result.html', result="Error: Command timed out.")
#
# # Explanation:  An attacker could inject malicious commands into the 'command' variable,
# # such as "ls -l ; rm -rf /" which would list files and then attempt to delete everything.
# # NEVER use shell=True with user-provided input.  Use the `subprocess` module's `args` parameter
# # to pass arguments safely.  Even better, avoid executing arbitrary commands based on user input.

# General Recommendations (with additions)

# ... (Existing recommendations)

# Content Security Policy (CSP): Implement a Content Security Policy (CSP) to control the sources from which the browser is allowed to load resources. This can help to mitigate XSS attacks.
# Example CSP header: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
# (This is a basic example; a real-world CSP would likely be more complex and restrictive.)

# Rate Limiting: Implement rate limiting to prevent brute-force attacks and other forms of abuse.  This can be done using libraries like Flask-Limiter or using a reverse proxy like Nginx.

# Authentication Strength: Use strong password hashing algorithms (e.g., bcrypt, Argon2) and salting passwords. Encourage users to use password managers.

# Dependency Vulnerabilities: Regularly scan dependencies for known vulnerabilities using tools like pip-audit (for Python) or npm audit (for Node.js).

