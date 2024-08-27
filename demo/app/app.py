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


@app.route('/')
def index():
    teams = db.session.execute(db.select(Teams)).scalars()
    return render_template('index.html', teams=teams)

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)