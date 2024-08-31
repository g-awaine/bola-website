import os
from dotenv import load_dotenv
import secrets
import hashlib
import hmac
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
    salt = db.Column(db.LargeBinary(16), nullable=False)
    hashed_password = db.Column(db.LargeBinary(32), nullable=False)

# create the tables
with app.app_context():
    db.create_all()


# define the forms used in the website

# defines the registration form used to register an account
class RegistrationForm(FlaskForm):
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

# defines a login form that logs the user into an account
class LoginForm(FlaskForm):
    # define custom form validators
    def username_does_not_exist(form, field):
        if Users.query.filter_by(username=field.data).first():
            raise ValidationError('Username does not exist')
        
    def username_does_not_exist(form, field):
        if Users.query.filter_by(username=field.data).first():
            raise ValidationError('Username does not exist')
        
    username = StringField('Username', 
                           validators=[DataRequired(), username_does_not_exist],
                           render_kw={"placeholder": "Username"})
    password = PasswordField('Password', 
                            validators=[DataRequired()],
                            render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# define the functions used
def create_secure_password(password, pepper):
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',  
        password.encode('utf-8') + pepper.encode('utf-8'), 
        salt, 
        100_000
    )
    
    return salt, password_hash


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
        plain_password = registration_form.password.data
        salt, hashed_password = create_secure_password(plain_password, pepper)
        new_user = Users(username=username, email=email, salt=salt, hashed_password=hashed_password)

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
            print(f'Error: {str(e)}', 'danger')
            return render_template('registration.html', form=registration_form)
    
    return render_template('registration.html', form=registration_form)

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)