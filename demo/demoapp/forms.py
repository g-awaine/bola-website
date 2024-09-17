import hashlib
import hmac
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError

from demoapp import db, pepper
from demoapp.models import *

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


class NewPostForm(FlaskForm):
    content = TextAreaField(label='Content')
    media = FileField(label='Upload a Picture', validators=[
        FileAllowed(('jpeg', 'jpg', 'png'))
    ])
    submit = SubmitField(label='Post')



class CommentPostForm(FlaskForm):
    content = TextAreaField(label='Comment')
    submit = SubmitField(label='Post')


