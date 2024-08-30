import os
from dotenv import load_dotenv
import secrets
import hashlib
from flask import Flask, session, render_template, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from markupsafe import escape

# Load environment variables from .env file
load_dotenv("../../.env")

host = "localhost:3307"
user = "user"
password = "password"
database_name = "Bola"
secret_key = secrets.token_urlsafe(16)
pepper = os.getenv('PEPPER')

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://' + user + ':' + password + '@' + host + '/' + database_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

csrf = CSRFProtect(app)
mysql = MySQL(app)

# initialize the app with Flask-SQLAlchemy
db = SQLAlchemy()
db.init_app(app)

# define the table model as an object
class Teams(db.Model):
    __tablename__ = 'Teams'
    team_id = db.Column(db.Integer, primary_key=True)
    team_name = db.Column(db.String)
    country = db.Column(db.String)
    wins = db.Column(db.Integer)
    losses = db.Column(db.Integer)
    points = db.Column(db.Integer)

class Teams_Icons(db.Model):
    __tablename__ = 'Teams_Icons'
    team_id = db.Column(db.Integer, primary_key=True)
    icon_name = db.Column(db.String, nullable=False)
    url = db.Column(db.String, nullable=False)
    upload_date = db.Column(db.Date, nullable=False)

# define the forms used in the website
class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired()],
                           render_kw={"placeholder": "Username"})
    email = StringField('Email', 
                        validators=[DataRequired(), Email(message='Invalid email address')],
                        render_kw={"placeholder": "Email"})
    password = PasswordField('Password', 
                            validators=[DataRequired()],
                            render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), 
                                                 EqualTo('password', message='Passwords must match')],
                                                 render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

# define the functions used
def create_secure_password(password):
  salt = secrets.token_urlsafe(16)
  iterations = 100_000 
  hash_value = hashlib.pbkdf2_hmac(
    'sha256',  
    password.encode('utf-8') + pepper.encode('utf-8'), 
    salt, 
    iterations
  )
  password_hash = salt + hash_value
  return password_hash


@app.route('/')
def index():
    leaderboard_results = db.session.execute(
        db.select(Teams, Teams_Icons.url)
        .select_from(Teams)
        .join(Teams_Icons, Teams.team_id == Teams_Icons.team_id)
    ).all()

    leaderboard_standings = [
        {
            'team_name': row[0].team_name,
            'country': row[0].country,
            'wins': row[0].wins,
            'losses': row[0].losses,
            'points': row[0].points,
            'url': row[1]
        }
        for row in leaderboard_results
    ]

    return render_template('index.html', leaderboard_standings=leaderboard_standings)


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    registration_form = RegistrationForm()
    if registration_form.validate_on_submit() and request.method == 'POST':
        return redirect(url_for('login'))
    
    return render_template('registration.html', form=registration_form)

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)