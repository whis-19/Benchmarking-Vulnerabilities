from flask_wtf import FlaskForm, CSRFProtect
   from wtforms import StringField, IntegerField, SubmitField
   from wtforms.validators import DataRequired, NumberRange

   app = Flask(__name__)
   app.config['SECRET_KEY'] = secrets.token_hex(16)  # Secure secret key
   csrf = CSRFProtect(app)

   class BuyStockForm(FlaskForm):
       stock_name = StringField('Stock Name', validators=[DataRequired()])
       quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
       submit = SubmitField('Buy')

   @app.route('/', methods=['GET', 'POST'])
   @login_required
   def index():
       form = BuyStockForm()
       if form.validate_on_submit():
           # Process the form data here
           stock_name = form.stock_name.data
           quantity = form.quantity.data
           # ... (rest of your buy_stock logic)
           return redirect(url_for('index'))
       return render_template('index.html', form=form)

