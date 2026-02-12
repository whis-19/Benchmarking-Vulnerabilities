@app.route('/protected')
   @login_required
   def protected():
       username = user_sessions.get(session.get('session_id'))
       response = make_response(render_template('protected.html', username=username))
       response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
       response.headers['Pragma'] = 'no-cache'
       response.headers['Expires'] = '0'
       return response

