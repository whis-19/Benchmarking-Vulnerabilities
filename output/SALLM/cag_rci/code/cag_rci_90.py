import bleach

        @app.route("/", methods=['GET', 'POST'])
        def index():
            form = InputForm()
            if form.validate_on_submit():
                ui_data = form.ui_data.data
                # Sanitize the input
                allowed_tags = ['b', 'i', 'em', 'strong', 'p', 'br']  # Define allowed HTML tags
                sanitized_data = bleach.clean(ui_data, tags=allowed_tags, strip=True)
                return render_template('result.html', ui_data=sanitized_data)
            return render_template('index.html', form=form)

