import os
import secrets
import hashlib
import hmac
from dotenv import load_dotenv
from markupsafe import escape
from itsdangerous import URLSafeTimedSerializer

from flask import Flask, session, render_template, redirect, request, url_for, flash
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_wtf import FlaskForm, CSRFProtect

from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError


# load environment variables from .env file
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


# define the forms used in the website

# define the custom validators used across the various forms


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
        # checks if the username exists in the database
        if Users.query.filter_by(username=field.data).first() is None:
            raise ValidationError('Username does not exist')
        
    def incorrect_password(form, field):
        #checks if the password is incorrect

        # checks to ensure that the username does exist and is valid by checking if an error was produced from the username field. 
        # if the username errors are empty it means the username passed the check and now the password can be checked
        if form.username.errors:
            return

        # identify the user
        user = Users.query.filter_by(username=form.username.data).first()

        # extract the salt and hashed password of the user
        salt = user.salt
        true_hashed_password = user.hashed_password

        # extract the inputted plain password and convert
        input_plain_password = field.data

        # hash the input_plain_password using the salt and pepper
        input_hashed_password = hashlib.pbkdf2_hmac(
                'sha256',  
                input_plain_password.encode('utf-8') + pepper.encode('utf-8'), 
                salt, 
                100_000
            )
        
        # compare the hashed passwords and raise error if they are not the same
        if not hmac.compare_digest(true_hashed_password, input_hashed_password):
            raise ValidationError('Incorrect password. Try Again')
        
    username = StringField('Username', 
                           validators=[DataRequired(), username_does_not_exist])
    password = PasswordField('Password', 
                            validators=[DataRequired(), incorrect_password],
                            render_kw={'id': 'password'})
    submit = SubmitField('Login')

# defines the form to allow the user to choose the email he wants to reset, given he follows the link sent via email
class RequestResetPasswordForm(FlaskForm):
    # define custom form validators
    def email_does_not_exist(form, field):
        # checks if the email does not exist in the database
        if db.session.execute(db.select(Users).filter_by(email=field.data)).scalar_one_or_none() is None:
            raise ValidationError('This email does not exist')
        
    email = StringField('Enter your email address:', 
                        validators=[DataRequired(), Email(message='Invalid email address'), email_does_not_exist],
                        render_kw={"placeholder": "Email"})
    
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    # asks user to input new password for that email
    password = PasswordField('New Password:', 
                            validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                     validators=[DataRequired(), 
                                                 EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

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


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit() and request.method == 'POST':
        return redirect(url_for('index'))

    return render_template('login.html', form=login_form)


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
            # add user and commit it to the database
            db.session.add(new_user)
            db.session.commit()
            
            # redirect login page
            return redirect(url_for('login'))

        except Exception as e:
            # Handle exceptions (e.g., duplicate entry or database error)
            db.session.rollback()
            print(f'Error: {str(e)}', 'danger')
            return render_template('registration.html', form=registration_form)
    
    return render_template('registration.html', form=registration_form)


@app.route('/request_reset_password', methods=['GET', 'POST'])
def request_reset_password():
    # asks the user for the email to reset
    request_reset_password_form = RequestResetPasswordForm()

    if request_reset_password_form.validate_on_submit():
        email = request_reset_password_form.email.data

        # generate a secure token and salt
        token = s.dumps(email, salt='password-reset-salt')

        # construct the password reset URL
        reset_url = url_for('reset_password', token=token, _external=True)

        # send email
        msg = Message('Password Reset Request', 
                        sender='noreply@bola.com', 
                        recipients=[email])
        
        msg.body = f'To reset your password, click the following link: {reset_url}'
        mail.send(msg)
        flash('Check your email for the password reset link.', 'info')
        return redirect(url_for('login'))

    return render_template('request_reset_password.html', form=request_reset_password_form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
    except Exception as e:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('request_reset'))
    reset_password_form = ResetPasswordForm()

    if reset_password_form.validate_on_submit():
        original_plain_password = reset_password_form.password.data
        salt, new_hashed_password = create_secure_password(original_plain_password, pepper)

        user = db.session.execute(db.select(Users).filter_by(email=email)).scalar_one()
        user.salt = salt
        user.hashed_password = new_hashed_password
        db.session.commit()
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=reset_password_form)


if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)