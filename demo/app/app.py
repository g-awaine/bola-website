import os
from dotenv import load_dotenv
import base64
import secrets
import hashlib
from flask import Flask, session, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
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
    team_name = db.Column(db.String(100))
    country = db.Column(db.String(50))
    wins = db.Column(db.Integer)
    losses = db.Column(db.Integer)
    points = db.Column(db.Integer)

class Teams_Icons(db.Model):
    __tablename__ = 'Teams_Icons'
    team_id = db.Column(db.Integer, primary_key=True)
    icon_name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.Text, nullable=False)
    upload_date = db.Column(db.Date, nullable=False)

class Users(db.Model):
    __tablename__ = 'Users'
    username = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)

# create the tables
with app.app_context():
    db.create_all()

# define custom form validators
def username_exists(form, field):
    if Users.query.filter_by(username=field.data).first():
        raise ValidationError('Username already taken. Please choose a different one.')

def username_length_check(form, field):
    if len(field.data) > 50:
        raise ValidationError('Username must be less than 50 characters')
    elif len(field.data) < 3:
        raise ValidationError('Username must be more than 3 characters')

def email_exists(form, field):
    if Users.query.filter_by(email=field.data).first():
        raise ValidationError('This email is already associated with an account. Please choose a different one.')


# define the forms used in the website
class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(), username_exists, username_length_check],
                           render_kw={"placeholder": "Username"})
    email = StringField('Email', 
                        validators=[DataRequired(), Email(message='Invalid email address'), email_exists],
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
def create_secure_password(password, pepper):
    salt = secrets.token_bytes(16)
    iterations = 100_000 
    hash_value = hashlib.pbkdf2_hmac(
        'sha256',  
        password.encode('utf-8') + pepper.encode('utf-8'), 
        salt, 
        iterations
    )

    # represent the salt and hash as base64 for storage
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(hash_value).decode('utf-8')

    # format the password hash to be delimited by a ":"
    password_hash = f"{salt_b64}:{hash_b64}"
    
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
        username = registration_form.username.data
        email = registration_form.email.data
        raw_password = registration_form.password.data
        hashed_password = create_secure_password(raw_password, pepper)
        new_user = Users(username=username, email=email, password=hashed_password)

        try:
            # Add the new user to the session and commit it to the database
            db.session.add(new_user)
            db.session.commit()
            
            # Redirect to the login page
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            # Handle exceptions (e.g., duplicate entry or database error)
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return render_template('registration.html', form=registration_form)
    
    return render_template('registration.html', form=registration_form)

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)