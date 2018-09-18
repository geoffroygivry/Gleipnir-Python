import os
from flask import Flask, render_template, url_for, request, session, redirect, Response, flash
from flask_pymongo import PyMongo
import bcrypt
import json

from config import glpr_config as cfg

from werkzeug.utils import secure_filename

dir_path = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = os.path.join(dir_path, 'tmp')
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
ALLOWED_XLS_EXTENSIONS = set(['xls', 'xlsx'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MONGO_DBNAME'] = 'gleipnir'
app.config['MONGO_URI'] = cfg.MONGODB


mongo = PyMongo(app)


@app.route('/')
def index():
    if 'username' in session:
        return render_template("index.html", user_session=session['username'])
    else:
        return render_template("index.html")


def redirect_url(default='index'):
    return request.args.get('next') or \
        request.referrer or \
        url_for(default)


def dirs_to_watch(extras_dirs):
    from os import path

    extra_dirs = [extras_dirs, ]
    extra_files = extra_dirs[:]
    for extra_dir in extra_dirs:
        for dirname, dirs, files in os.walk(extra_dir):
            for filename in files:
                filename = path.join(dirname, filename)
                if path.isfile(filename):
                    extra_files.append(filename)
    return extra_files


@app.route('/login')
def login():
    name = request.args.get('name')
    password = request.args.get('password')
    users = mongo.db.users
    login_user = users.find_one({'name': name})

    if login_user:
        if bcrypt.hashpw(password.encode('utf-8'), login_user['password'].encode('utf-8')) == login_user['password'].encode('utf-8'):
            session['username'] = name
            return "all good"

    return 'Invalid username/password combination'


@app.route('/register')
def register():
    name = request.args.get('name')
    password = request.args.get('password')
    email = request.args.get('email')
    # return "{} {} {}".format(name, password, email)

    users = mongo.db.users
    existing_user = users.find_one({'name': name})

    if existing_user is None:
        hashpass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users.insert({'name': name, 'password': hashpass, 'email': email})
        session['username'] = name
        return "user registered."

    return "existing user"


@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username', None)
        return redirect(url_for('index'))


if __name__ == "__main__":
    app.secret_key = cfg.FLASK_APP_SECRET_KEY
    app.run(debug=True, host="0.0.0.0", extra_files=dirs_to_watch("templates"))
