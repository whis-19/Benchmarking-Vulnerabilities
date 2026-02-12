from flask_talisman import Talisman

app = Flask(__name__)
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'img-src': '*'  # Adjust as needed, be specific!
})

