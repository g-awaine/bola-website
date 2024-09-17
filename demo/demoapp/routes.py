from flask import render_template, redirect, request, url_for, flash, jsonify, send_from_directory
from flask_mail import Message
from flask_login import login_user, login_required, logout_user, current_user

from demoapp import app, db, csrf, mysql, mail, s, login_manager
from demoapp.forms import *
from demoapp.models import *
from demoapp.utils import *


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
    # if current_user.is_authenticated:
    #     return redirect(url_for('index'))
    
    login_form = LoginForm()
    if login_form.validate_on_submit() and request.method == 'POST':
        username = login_form.username.data
        user = db.session.execute(db.select(Users).filter_by(username=username)).scalar_one()
        login_user(user, remember=False)
        return redirect(url_for('index'))

    return render_template('login.html', form=login_form)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    # if current_user.is_authenticated:
    #     return redirect(url_for('index'))
    
    registration_form = RegistrationForm()
    if registration_form.validate_on_submit() and request.method == 'POST':
        user_id = generate_unique_id(Users, 'user_id')
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
        logout_user()
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


@app.route("/explore", methods=['GET', 'POST'])
def explore():
    if request.method == 'GET':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return render_template("explore.html")

    if request.method == 'POST':
        print('Received POST request')
        start = int(request.json.get('start') or 1)
        # get posts along with the author/username of the poster
        posts = db.session.query(Posts, Users.username).outerjoin(Users, Posts.user_id == Users.user_id).paginate(page=start, per_page=3, error_out=False).items
        result = []
        for post, username in posts:
            result.append(
                {
                    'post_url': url_for('get_post', post_id=post.post_id),
                    'content': post.content,
                    'media': url_for('serve_static', filename='media/mid' + post.media),
                    'date_posted': post.date_posted,
                    'username': username,
                    'like_count': post.get_likes_count(),
                    'comment_count': post.comments_count(),
                    'comments': post.get_comments(limit=5)
                }
            )
        status = True
        return jsonify(result=result, success=status)

# temporary function to show the static images from the file system
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    new_post_form = NewPostForm()
    if new_post_form.validate_on_submit():
        post_id = generate_unique_id(Posts, 'post_id')
        media = save_media(new_post_form.media.data, 'media')
        date_posted = datetime.now(timezone.utc)
        post = Posts(post_id=post_id, content=new_post_form.content.data, media=media, author=current_user, date_posted=date_posted)
        db.session.add(post)
        db.session.commit()
        flash("Posted successfully", 'success')
        return redirect(url_for('index'))
    return render_template("new_post.html", form=new_post_form)


@app.route("/post/id/<string:post_id>")
def get_post(post_id):
    # post_id = request.args.get('post_id')
    post = Posts.query.get_or_404(post_id)

    return render_template("post.html", post=post, get_file_url=get_file_url)


@app.route("/post/<string:post_id>/delete")
@login_required
def delete_post(post_id):
    post = Posts.query.get_or_404(post_id)

    if post.author == current_user:
        db.session.query(Comments).filter(Comments.post_id == post.post_id).delete()
        db.session.query(Notif).filter(Notif.post_id == post.post_id).delete()
        delete_file(post.media)
        db.session.delete(post)
        db.session.commit()
        flash("Post deleted", 'success')
        return redirect(url_for('index'))
    else:
        flash("You don't have delete privilege for that post!", 'danger')
        return redirect(url_for('index'))

@app.route("/user/<string:username>")
def get_user(username):
    user = Users.query.filter_by(username=username).first_or_404()
    posts = user.posts
    posts.reverse()
    return render_template("user.html", title=user.username, posts=posts, user=user, get_file_url=get_file_url)


