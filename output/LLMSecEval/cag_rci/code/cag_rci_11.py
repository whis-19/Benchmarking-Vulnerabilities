# Example: AJAX CSRF handling (JavaScript)
<script>
  function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      const cookies = document.cookie.split(';');
      for (let i = 0; i < cookies.length; i++) {
        let cookie = cookies[i].trim();
        // Does this cookie string begin with the name we want?
        if (cookie.substring(0, name.length + 1) === (name + '=')) {
          cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }

  const csrftoken = getCookie('csrf_token');

  function sendAjaxRequest() {
    fetch('/your_endpoint', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken  // Include CSRF token in the header
      },
      body: JSON.stringify({ data: 'your data' })
    })
    .then(response => response.json())
    .then(data => {
      console.log(data);
    });
  }
</script>

# Example: Server-side validation of the CSRF token (if not using Flask-WTF forms)
from flask import request, jsonify

@app.route('/your_endpoint', methods=['POST'])
def your_endpoint():
  csrf_token = request.headers.get('X-CSRFToken')
  if not csrf_token or csrf_token != session.get('csrf_token'):  # Validate the token
    return jsonify({'error': 'CSRF token validation failed'}), 400

  # ... (rest of your logic)

