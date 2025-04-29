#Name: Kamil Roginski
#Date: 28 APR 2025
#Professor: Mark Babcock
#Course: CYOP 300

"""
Lab 7: Core Flask application that implements user registration, login, session management,
route protection, flash messaging, and a debug endpoint to inspect registered users.
"""

import os
import re
from functools import wraps
from datetime import datetime as dt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# In-memory user store: {username: password_hash}
users = {}

def password_complexity(password):
    """
    Return True if the password meets minimum length and character-type requirements.
    """
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


def login_required(f):
    """
    Decorator that redirects to login if no user is currently authenticated.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access that page.')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return wrapped

@app.route('/')
@login_required
def home():
    """
    Render the home page showing the current date and time to a logged-in user.
    """
    now = dt.now()
    return render_template('home.html', now=now)

@app.route('/about')
@login_required
def about():
    """
    Render the about page for authenticated users.
    """
    return render_template('about.html')

@app.route('/contact')
@login_required
def contact():
    """
    Render the contact page for authenticated users.
    """
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handle user sign-up by validating inputs, storing a hashed password, and flashing status.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        if username in users:
            flash('Username already exists.')
        elif password != confirm:
            flash('Passwords do not match.')
        elif not password_complexity(password):
            flash('Password must be ≥12 chars and include upper, lower, digit, special.')
        else:
            users[username] = generate_password_hash(password)
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Authenticate a user by verifying their credentials and starting a session.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pwd_hash = users.get(username)
        if pwd_hash and check_password_hash(pwd_hash, password):
            session['username'] = username
            flash('Logged in successfully.')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Log out the current user by clearing their session and redirecting to login.
    """
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
