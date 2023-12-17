import random
import string

from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_session import Session
import secrets
from datetime import datetime, timedelta
import sqlite3
import os
import shortuuid



app = Flask(__name__)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.secret_key = secrets.token_hex(16)
Session(app)
app = Flask(__name__)
shortened_urls={}
bcrypt = Bcrypt(app)
app.secret_key = secrets.token_hex(16)
instance_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance'))

db_path = os.path.join(instance_path, 'user.db')
url_db_path = os.path.join(instance_path, 'url.db')
user_conn = sqlite3.connect(db_path, check_same_thread=False)
url_conn = sqlite3.connect(url_db_path, check_same_thread=False)
user_cursor = user_conn.cursor()
url_cursor = url_conn.cursor()

user_cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
""")
user_conn.commit()

url_cursor.execute("""
    CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        short_url TEXT NOT NULL,
        original_url TEXT NOT NULL,
        expiration_time TEXT NOT NULL,
        username TEXT NOT NULL,
        FOREIGN KEY (username) REFERENCES users (username)
    )
""")
url_conn.commit()
# Dummy database for users and links
users = {'username': 'password'}  # Replace with a proper database
links = {}  # Replace with a proper database

@app.route('/')
def index():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            # Connect to SQLite database
            conn = sqlite3.connect(db_path, check_same_thread=False)
            cursor = conn.cursor()

            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                return render_template('signup.html', message="Username already exists. Choose another.")
            else:
                # Insert new user into the database
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                return redirect(url_for('login'))

        except sqlite3.Error as e:
            # Handle SQLite database error
            print("SQLite error:", e)

        finally:
            # Close the database connection in the finally block
            if conn:
                conn.close()

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Retrieve hashed password from the database
        user_cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = user_cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            # Passwords match, set the username in the session
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', message="Invalid username or password")

    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/shorten', methods=['POST'])
def shorten():
    if 'username' in session:
        original_url = request.form['original_url']
        short_url = generate_short_url()
        while short_url in shortened_urls:
            short_url=generate_short_url()
        shortened_urls[short_url]=original_url
        short_url = f"{request.url_root}{short_url}"

        expiration_time = datetime.now() + timedelta(days=1)

        try:
            print(f"Original URL: {original_url}")
            print(f"Generated Short URL: {short_url}")

            url_cursor.execute("""
                INSERT INTO urls (short_url, original_url, expiration_time, username)
                VALUES (?, ?, ?, ?)
            """, (short_url, original_url, expiration_time, session['username']))
            url_conn.commit()

            # You can optionally redirect to the index or any other page
            return redirect(url_for('index'))
        except sqlite3.Error as e:
            print("SQLite error:", e)
            return redirect(url_for('index'))

    return redirect(url_for('login'))
@app.route('/analytics')
def analytics():
    if 'username' in session:
        try:
            url_cursor.execute("""
                SELECT short_url, original_url, expiration_time
                FROM urls
                WHERE username = ?
            """, (session['username'],))
            user_links = url_cursor.fetchall()
        except sqlite3.Error as e:
            print("SQLite error:", e)
            user_links = []



        return render_template('analytics.html', links=user_links)
    return redirect(url_for('login'))

@app.route("/<short_url>")
def redirect_url(short_url):
    long_url=shortened_urls.get(short_url)
    if long_url:
        return redirect(long_url)
    else:
        return  "URL Not found at ",404
def generate_short_url(length=6):
    chars=string.ascii_letters+string.digits
    short_url="".join(random.choice(chars) for _ in range(length))
    return short_url

if __name__ == '__main__':
    app.run(debug=True)
