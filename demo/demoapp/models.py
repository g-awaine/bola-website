from datetime import datetime, timezone
from flask_login import UserMixin
import timeago
import random

from demoapp import app, db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(Users).filter_by(user_id=user_id)).scalar_one()


followers = db.Table('followers',
    db.Column('user_id', db.String(36), db.ForeignKey('Users.user_id')),
    db.Column('follows_id', db.String(36), db.ForeignKey('Users.user_id'))
)


likes = db.Table('likes',
    db.Column('post_id', db.String(36), db.ForeignKey('Posts.post_id')),
    db.Column('user_id', db.String(36), db.ForeignKey('Users.user_id'))
)

# define the table model as an object
class Teams(db.Model):
    __tablename__ = 'Teams'
    team_id = db.Column(db.String(36), primary_key=True)
    team_name = db.Column(db.String(100))
    country = db.Column(db.String(50))
    wins = db.Column(db.Integer)
    losses = db.Column(db.Integer)
    points = db.Column(db.Integer)


class Teams_Icons(db.Model):
    __tablename__ = 'Teams_Icons'
    team_id = db.Column(db.String(36), primary_key=True)
    icon_name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.Text, nullable=False)
    upload_date = db.Column(db.Date, nullable=False)


class Users(UserMixin, db.Model):
    __tablename__ = 'Users'
    
    user_id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.Text, nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)
    hashed_password = db.Column(db.LargeBinary(32), nullable=False)
    image_url = db.Column(db.Text, nullable=False, default='default.jpg')
    notif_count = db.Column(db.Integer, default=0)

    posts = db.relationship('Posts', backref='author', lazy=True)
    comments = db.relationship('Comments', backref='author', lazy=True)  

    follows = db.relationship(
        'Users', secondary=followers,
        primaryjoin=(followers.c.user_id == user_id),
        secondaryjoin=(followers.c.follows_id == user_id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    notifs = db.relationship('Notif', backref='notif_for', lazy=True)  
    

    # define the function to retrueve the user id
    def get_id(self):
        return self.user_id

    def get_notifs(self):
        if self.new_notif():
            limit = len(self.notifs) - self.notif_count
            # print(len(self.notifs), self.notif_count)
            l = self.notifs[-limit:]
            l.reverse()
            return l

    def get_old_notifs(self):
        limit = len(self.notifs) - self.notif_count
        
        self.notif_count = len(self.notifs)
        db.session.commit()
        
        if limit == 0:
            l = self.notifs[-4:]
        else:
            l = self.notifs[-4:-limit]
        l.reverse()
        return l
        # print(self.notif_count, self.notifs[-4:])

    def new_notif(self):
        return len(self.notifs) > self.notif_count

    def post_count(self):
        return len(self.posts)

    def is_following(self, user):
        l = self.follows.filter(followers.c.follows_id == user.user_id).count()
        return l > 0

    def follow(self, user):
        if self.user_id != user.user_id:
            if not self.is_following(user):
                self.follows.append(user)


    def unfollow(self, user):
        if self.is_following(user):
            self.follows.remove(user)


    def get_followers(self, user):
        return Users.query.filter(Users.follows.any(user_id=user.user_id)).all()


    def get_followers_count(self, user):
        return len(self.get_followers(user))


    def get_followed_posts(self):
        fw_users = [user.user_id for user in self.follows.all()]
        fw_users.append(self.user_id)       # to include my own posts
        # print(fw_users)
        fw_posts = Posts.query.order_by(Posts.date_posted.desc()).filter(Posts.user_id.in_(fw_users))
        return fw_posts 


    def get_user_suggestion(self):
        user_follows = self.follows
        avoid = [user.user_id for user in user_follows]
        avoid.append(self.user_id)

        available_users = Users.query.filter(Users.user_id.notin_(avoid)).all()        
        if len(available_users) == 0:
            return []
        elif len(available_users) <= 2:
            return available_users

        # find sugg users
        suggs = []
        while len(suggs) < 2:
            index = random.randint(0, len(available_users)-1)
            user = available_users[index]
            if user not in suggs:
                suggs.append(user)

        # print(suggs)
        return suggs


    def __repr__(self):
        return f"User('{self.username}', '{self.password}', '{self.image_file}')"


class Posts(db.Model):
    __tablename__ = 'Posts'
    post_id = db.Column(db.String(36), primary_key=True)
    content = db.Column(db.Text, nullable=False)
    media = db.Column(db.String(32), nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    user_id = db.Column(db.String(36), db.ForeignKey('Users.user_id'), nullable=False)

    liked = db.relationship("Users", secondary=likes)
    comments = db.relationship('Comments', backref='post', lazy=True)
    notifs = db.relationship('Notif', backref='post', lazy=True)


    def get_likes_count(self):
        return len(self.liked)


    def user_liked(self, user):
        return user in self.liked


    def like_post(self, user):
        if user not in self.liked:
            self.liked.append(user)
            return "like"
        else:
            self.unlike_post(user)
            return "unlike"


    def unlike_post(self, user):
        self.liked.remove(user)


    def comments_count(self):
        return len(self.comments)


    def get_comments(self, limit=0):
        if limit > 0:
            return self.comments[-limit:] 


    def get_timeago(self):
        now = datetime.now()
        return timeago.format(self.date_posted, now)


    def __repr__(self):
        return f"Post('{self.content}', '{self.date_posted}')"


class Comments(db.Model):
    __tablename__ = 'Comments'
    comment_id = db.Column(db.String(36), primary_key=True)
    content = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.String(36), db.ForeignKey('Posts.post_id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('Users.user_id'), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

    def __repr__(self):
        return f"Comment({self.post_id}, {self.user_id}, '{self.content}', '{self.date_posted}')"


class Notif(db.Model):
    __tablename__ = 'Notifs'
    notification_id = db.Column(db.String(36), primary_key=True)
    msg = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.String(36), db.ForeignKey('Posts.post_id'), nullable=False)
    for_user_id = db.Column(db.String(36), db.ForeignKey('Users.user_id'), nullable=False)
    author = db.Column(db.String(50), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))

    @staticmethod
    def add_notif(user, post, n_type):
        notif_for = post.author.user_id
        n = Notif(for_uid=notif_for, post_id=post.post_id, msg=n_type, author=user.username)
        return n

    def __repr__(self):
        return f"{self.author} {self.msg} your post({self.post_id})"
    

# create the tables
with app.app_context():
    db.create_all()