from contextlib import contextmanager

    @contextmanager
    def get_db_connection():
        conn = get_connection()
        try:
            yield conn
        finally:
            release_connection(conn)

    # Then, in your route:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT temperature FROM temperatures WHERE latitude = ? AND longitude = ? AND date = ?",
                (latitude, longitude, date)
            )
            result = cursor.fetchone()

        if result:
            temperature = result[0]
            return jsonify({'temperature': temperature}), 200
        else:
            return jsonify({'message': 'Temperature data not found for the given location and date'}), 404

    except Exception as e:
        print(f"Error: {e}")  # Log the error for debugging
        return jsonify({'error': 'Internal server error'}), 500

