ALLOWED_REGEXES = {
            "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "phone": r"^\d{3}-\d{3}-\d{4}$",
            # ... other predefined regexes
        }

        @app.route("/search", methods=['GET'])
        def search():
            regex_name = request.args.get("regex_name")
            text = request.args.get("text")

            if not regex_name or not text:
                return jsonify({"error": "Missing 'regex_name' or 'text' parameter"}), 400

            if regex_name not in ALLOWED_REGEXES:
                return jsonify({"error": "Invalid regex name"}), 400

            pattern = ALLOWED_REGEXES[regex_name]
            # ... rest of the search logic

