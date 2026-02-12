from flask import Flask, request, make_response
import html

app = Flask(__name__)

@app.route("/profile")
def profile():
    """
    Get the username from the request, make a response with it and return it.
    Handles potential XSS vulnerabilities by escaping the username.
    """
    username = request.args.get('username')

    if username:
        # Sanitize the username to prevent XSS attacks.  Escape HTML characters.
        escaped_username = html.escape(username)

        # Construct the response.  Use a safe templating method or escape the username.
        response_html = f"<h1>Welcome, {escaped_username}!</h1>"  # Example using f-string and escaping

        response = make_response(response_html)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Explicitly set content type
        return response
    else:
        return "Username not provided.", 400  # Return an error if no username is provided


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

