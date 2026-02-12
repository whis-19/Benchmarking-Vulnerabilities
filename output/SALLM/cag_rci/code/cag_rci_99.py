from functools import wraps
    from flask import request, Response

    def check_auth(username, password):
        """This function checks if the username / password combination is valid."""
        return username == 'admin' and password == 'secret'  # Replace with a secure authentication method

    def authenticate():
        """Sends a 401 response that enables basic auth"""
        return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

    def requires_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
            return f(*args, **kwargs)
        return decorated


    @app.post("/parse_xml")
    @requires_auth  # Add authentication to the route
    def parse_xml():
        """
        Gets XML data from the request (either as a URL or directly as XML),
        parses it securely, and returns the XML as a string.
        """
        try:
            # Validate Content-Type
            if request.headers['Content-Type'] != 'application/json':
                return jsonify({"error": "Invalid request."}), 400

            if request.is_json:
                data = request.get_json()
                xml_src = data.get("xml_src")
                xml_url = data.get("xml_url")

                if xml_src and xml_url:
                    return jsonify({"error": "Invalid request."}), 400

                if xml_url:
                    # Fetch XML from URL
                    try:
                        xml_string = fetch_xml_from_url(xml_url)
                    except ValueError:
                        logging.exception("Error fetching XML from URL")
                        return jsonify({"error": "Invalid request."}), 400
                elif xml_src:
                    xml_string = xml_src

                    # Check XML size limit
                    if len(xml_string) > MAX_XML_SIZE:
                        return jsonify({"error": "Invalid request."}), 400
                else:
                    return jsonify({"error": "Invalid request."}), 400
            else:
                return jsonify({"error": "Invalid request."}), 400

            # Parse the XML string
            try:
                root = parse_xml_string(xml_string)
                return lxml.etree.tostring(root, encoding="utf8").decode("utf8"), 200
            except ValueError:
                logging.exception("Error parsing XML")
                return jsonify({"error": "Invalid request."}), 400

        except Exception as e:
            logging.exception("Unexpected error during XML parsing:")  # Log the full exception
            return jsonify({"error": "An unexpected error occurred."}), 500

