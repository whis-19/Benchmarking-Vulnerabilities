from flask_wtf import FlaskForm
   from wtforms import StringField, IntegerField, SubmitField
   from wtforms.validators import DataRequired, NumberRange

   app.config['WTF_CSRF_SECRET_KEY'] = secrets.token_hex(16)  # CSRF secret key

   class BuyOrderForm(FlaskForm):
       stock_name = StringField('Stock Name', validators=[DataRequired()])
       quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
       submit = SubmitField('Buy')

   @app.route('/')
   def index():
       form = BuyOrderForm()
       return render_template('index.html', form=form)

   @app.route('/buy_order', methods=['POST'])
   def buy_order():
       form = BuyOrderForm()
       if form.validate_on_submit():
           stock_name = form.stock_name.data
           quantity = form.quantity.data

           # Database interaction (same as before)
           try:
               db = get_db_connection()
               cursor = db.cursor()
               cursor.execute("INSERT INTO orders (stock_name, quantity) VALUES (?, ?)", (stock_name, quantity))
               db.commit()
               db.close()
           except sqlite3.Error as e:
               print(f"Database error: {e}")
               return "Error: Failed to insert data into the database."

           return redirect(url_for('stock_view'))
       else:
           return render_template('index.html', form=form) # Re-render form with errors

