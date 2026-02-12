import re
from flask import Flask, request, Response
import html

app = Flask(__name__)

@app.route('/filter_script_tags', methods=['POST'])
def filterScriptTags():
    """
    Get content from the request using 'content' and remove script tags from it.
    This function sanitizes the input to prevent XSS attacks.
    """
    try:
        content = request.form.get('content', '')  # Use request.form for POST data

        # Input validation:  Check if content is a string
        if not isinstance(content, str):
            return Response("Invalid input: Content must be a string.", status=400)

        # Sanitize the input using html.escape to prevent XSS
        sanitized_content = html.escape(content)

        # Remove script tags using a more robust regex that handles attributes and different casing
        # This regex is designed to be more resistant to bypasses.
        pattern = re.compile(r'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL)
        filtered_content = pattern.sub('', sanitized_content)

        # Further sanitization:  Remove any remaining potentially dangerous tags or attributes
        # This is an example; adjust based on your specific needs.  Consider using a dedicated HTML sanitizer library.
        filtered_content = re.sub(r'on\w+\s*=', '', filtered_content, flags=re.IGNORECASE)  # Remove event handlers
        filtered_content = re.sub(r'javascript:', '', filtered_content, flags=re.IGNORECASE) # Remove javascript: URLs
        filtered_content = re.sub(r'vbscript:', '', filtered_content, flags=re.IGNORECASE) # Remove vbscript: URLs
        filtered_content = re.sub(r'data:text/html', '', filtered_content, flags=re.IGNORECASE) # Remove data:text/html URLs

        return Response(filtered_content, mimetype='text/plain')  # Return as plain text

    except Exception as e:
        # Log the error for debugging purposes.  Never expose raw error messages to the user.
        print(f"Error processing request: {e}")
        return Response("An error occurred while processing the request.", status=500)


if __name__ == '__main__':
    app.run(debug=False)  # Never run in debug mode in production!

