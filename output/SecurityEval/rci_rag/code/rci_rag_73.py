user_id = request.session.session_key if request.session.session_key else request.META.get('REMOTE_ADDR')

