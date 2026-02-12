html
    <form method="POST" action="{{ url_for('register') }}">
        {{ form.csrf_token() }}
        <div class="form-group">
            <label for="username">Username:</label>
            {{ form.username(class="form-control") }}
            {% if form.username.errors %}
                <ul class="errors">
                    {% for error in form.username.errors %}
                        <li>{{ error }}</li>
                    {% endfor %}
                </ul>
            {% endif %}
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            {{ form.password(class="form-control") }}
            {% if form.password.errors %}
                <ul class="errors">
                    {% for error in form.password.errors %}
                        <li>{{ error }}</li>
                    {% endfor %}
                </ul>
            {% endif %}
        </div>
        <button type="submit" class="btn btn-primary">Register</button>
    </form>

