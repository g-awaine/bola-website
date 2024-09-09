import uuid
from flask import render_template, redirect, request, url_for, flash
from flask_mail import Message
from flask_login import login_user, login_required, logout_user, current_user

from app import app, db, csrf, mysql, mail, s, login_manager
from app.forms import *
from app.models import *

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
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    login_form = LoginForm()
    if login_form.validate_on_submit() and request.method == 'POST':
        username = login_form.username.data
        user = db.session.execute(db.select(Users).filter_by(username=username)).scalar_one()
        login_user(user, remember=False)
        return redirect(url_for('index'))

    return render_template('login.html', form=login_form)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    registration_form = RegistrationForm()
    if registration_form.validate_on_submit() and request.method == 'POST':
        user_id = str(uuid.uuid4())
        username = registration_form.username.data
        email = registration_form.email.data
        plain_password = registration_form.password.data
        salt, hashed_password = create_secure_password(plain_password, pepper)
        new_user = Users(user_id=user_id, username=username, email=email, salt=salt, hashed_password=hashed_password)

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


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


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
        print('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('request_reset_password'))
    reset_password_form = ResetPasswordForm()

    if reset_password_form.validate_on_submit():
        original_plain_password = reset_password_form.password.data
        salt, new_hashed_password = create_secure_password(original_plain_password, pepper)

        user = db.session.execute(db.select(Users).filter_by(email=email)).scalar_one()
        user.salt = salt
        user.hashed_password = new_hashed_password
        db.session.commit()
        
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=reset_password_form, token=token)
