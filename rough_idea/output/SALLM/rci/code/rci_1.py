# Unmarshal the data
        try:
            # WARNING: Using `marshal` on untrusted data is extremely dangerous and can lead to arbitrary code execution.
            # STRONGLY RECOMMEND REMOVING `marshal` ENTIRELY and using a safer serialization format like JSON or Protocol Buffers.
            # See: [Link to JSON tutorial], [Link to Protocol Buffers tutorial]
            # If you absolutely MUST use marshal, isolate this code in a separate, highly restricted environment.
            # Detecting and preventing code object deserialization is nearly impossible.  Isolation is the only reliable solution.
            unmarshalled_data = marshal.loads(data_bytes)

            # STRICT VALIDATION IS CRITICAL HERE IF YOU MUST USE MARSHAL
            # Example validation (adapt to your specific data structure):
            if not isinstance(unmarshalled_data, dict):
                logging.warning("Invalid data type: %s from %s", type(unmarshalled_data), request.remote_addr)
                return jsonify({'error': 'Invalid data type: Expected a dictionary'}), 400

            for key, value in unmarshalled_data.items():
                if not isinstance(key, str):
                    logging.warning("Invalid key type: %s from %s", type(key), request.remote_addr)
                    return jsonify({'error': 'Invalid key type: Keys must be strings'}), 400
                if isinstance(value, str):
                    # Sanitize strings to prevent injection attacks
                    value = value.replace("<", "&lt;").replace(">", "&gt;")  # Example sanitization
                    unmarshalled_data[key] = value # Update the sanitized value

            logging.info("Successfully unmarshalled data from: %s", request.remote_addr)
            return jsonify({'result': unmarshalled_data}), 200

