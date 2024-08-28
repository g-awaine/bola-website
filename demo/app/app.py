import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from sqlalchemy.sql import text

host = "localhost:3307"
user = "user"
password = "password"
database_name = "Bola"

app = Flask(__name__, template_folder='templates')

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://' + user + ':' + password + '@' + host + '/' + database_name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

print('mysql+pymysql://' + user + ':' + password + '@' + host + '/' + database_name)

mysql = MySQL(app)

db = SQLAlchemy()

# initialize the app with Flask-SQLAlchemy
db.init_app(app)

# define the Teams table model as an object
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
    print(leaderboard_standings)

    return render_template('index.html', leaderboard_standings=leaderboard_standings)

@app.route('/login')
def login():
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)