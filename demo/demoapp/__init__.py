import os
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer

from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_wtf import CSRFProtect
from flask_login import LoginManager
from flask_migrate import Migrate


# load environment variables from .env file
load_dotenv("../../.env")

host = "localhost:3307"
user = "user"
password = "password"
database_name = "Bola"
secret_key = os.getenv('SECRET_KEY')
pepper = os.getenv('PEPPER')

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = secret_key

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://' + user + ':' + password + '@' + host + '/' + database_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] =  os.getenv('SMTP_EMAIL')
app.config['MAIL_PASSWORD'] =  os.getenv('SMTP_EMAIL_PASSWORD')

csrf = CSRFProtect(app)
mysql = MySQL(app)

# initialise the mail api
mail = Mail(app)

# initialise the timeout functionality
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# initialize the app with Flask-SQLAlchemy
db = SQLAlchemy()
db.init_app(app)

# initialise the app with flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # redirect to the login page if login is required

# initialisation flask-migrate
migrate = Migrate(app, db)


from demoapp import routes