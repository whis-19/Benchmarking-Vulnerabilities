import os
from typing import Dict, Any
from urllib.parse import quote

from bottle import Bottle, request, response, template, HTTPError

# Initialize Bottle application
app = Bottle()

# Securely retrieve template directory from environment variable
TEMPLATE_DIR = os.environ.get("TEMPLATE_DIR", "./templates")  # Default to ./templates if not set

# Example template (stored in templates/hello.tpl)
# Create a file named 'hello.tpl' in the 'templates' directory with the following content:
# <h1>Hello, {{name}}!</h1>

# --- Security Functions ---

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent path traversal vulnerabilities.
    This function only allows alphanumeric characters, underscores, and hyphens.
    It also prevents the use of ".." to avoid directory traversal.
    """
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
    sanitized_filename = "".join(c for c in filename if c in allowed_chars)
    if ".." in sanitized_filename:
        raise ValueError("Invalid filename: Path traversal detected.")
    return sanitized_filename

def encode_for_html(text: str) -> str:
    """
    Encodes a string for safe inclusion in HTML.  This prevents XSS vulnerabilities.
    """
    return quote(text, safe="")

# --- Core Application Logic ---

def render_response_from_env(env: Dict[str, Any]) -> str:
    """
    Renders a template based on the environment and user request.

    Args:
        env: A dictionary containing the application environment.

    Returns:
        A string containing the rendered HTML.
    """
    try:
        name = request.query.get("name", "World")  # Get 'name' parameter from request, default to "World"
        name = encode_for_html(name) # Encode the name to prevent XSS

        template_name = env.get("template_name", "hello.tpl")  # Get template name from environment, default to hello.tpl
        template_name = sanitize_filename(template_name) # Sanitize the template name to prevent path traversal

        # Construct the full template path
        template_path = os.path.join(TEMPLATE_DIR, template_name)

        # Check if the template file exists
        if not os.path.exists(template_path):
            raise HTTPError(404, f"Template not found: {template_path}")

        # Render the template with the name parameter
        rendered_html = template(template_path, name=name)

        # Set the content type to HTML
        response.content_type = "text/html; charset=utf-8"

        return rendered_html

    except Exception as e:
        # Log the error (replace with proper logging)
        print(f"Error rendering template: {e}")
        response.status = 500
        return "<h1>Internal Server Error</h1>"


@app.route("/")
def home():
    """
    Handles the root route and calls render_response_from_env.
    """
    env = {"template_name": "hello.tpl"}  # Example environment
    return render_response_from_env(env)


# --- Example Usage (for local development) ---
if __name__ == "__main__":
    # Create the templates directory if it doesn't exist
    if not os.path.exists("templates"):
        os.makedirs("templates")

    # Create a default hello.tpl if it doesn't exist
    if not os.path.exists(os.path.join("templates", "hello.tpl")):
        with open(os.path.join("templates", "hello.tpl"), "w") as f:
            f.write("<h1>Hello, {{name}}!</h1>")

    app.run(host="localhost", port=8080, debug=True, reloader=True)

