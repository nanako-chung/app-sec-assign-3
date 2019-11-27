from flask import Flask, render_template, request, redirect, url_for, session
from flask_paranoid import Paranoid
from flask_login import LoginManager, UserMixin, login_user, current_user
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect()
import hashlib
import re
import subprocess
# Create dict with key as user and value as { password, 2fa }
accounts = {}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'top-secret!'
    csrf.init_app(app)
    login_manager = LoginManager(app)

    @login_manager.user_loader
    def load_user(id):
        return User(id)

    login_manager.session_protection = 'strong'
    paranoid = Paranoid(app)
    paranoid.redirect_view = '/login'

    @paranoid.on_invalid_session
    def invalid_session():
        return 'Please login', 401

    # http://localhost:5000/login - this will be the login page, we need to use both GET and POST requests
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # Output message if something goes wrong...
        msg = ''
        # Check if 'username' and 'password' POST requests exist (user submitted form)
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'two_factor_auth' in request.form:
            # Create variables for easy access
            username = request.form['username']
            password = request.form['password']
            hashedPassword = hashlib.md5(password.encode('utf-8')).hexdigest()
            two_factor_auth = request.form['two_factor_auth']

            # Check if account exists using dict
            account = {}
            if username in accounts and accounts[username]['password'] == hashedPassword:
                if accounts[username]['two_factor_auth'] == two_factor_auth:
                    # Fetch one record from dict and return result
                    account['username'] = username
                    account['password'] = hashedPassword
                    account['two_factor_auth'] = two_factor_auth
                    # Account exists in accounts dict in out database
                    # Create session data, we can access this data in other routes
                    session['logged_in'] = True
                    login_user(User(username))
                    msg = 'Success!'
                else:
                    msg = 'Failure: Incorrect two-factor authentication'
            else:
                # Account doesnt exist or username/password incorrect
                msg = 'Failure: Incorrect username or password'
        return render_template('index.html', msg=msg)

    # http://localhost:5000/register - this will be the registration page, we need to use both GET and POST requests
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        # Output message if something goes wrong...
        msg = ''
        # Check if 'username' and 'password' POST requests exist (user submitted form)
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'two_factor_auth' in request.form:
            # Create variables for easy access
            username = request.form['username']
            password = request.form['password']
            hashedPassword = hashlib.md5(password.encode('utf-8')).hexdigest()
            two_factor_auth = request.form['two_factor_auth']

            # Check if account exists using dict
            account = {}
            if username in accounts:
                if accounts[username]['password'] == hashedPassword and accounts[username]['two_factor_auth'] == two_factor_auth:
                    # Fetch one record from dict and return result
                    account['username'] = username
                    account['password'] = hashedPassword
                    account['two_factor_auth'] = two_factor_auth

            # If account exists in accounts dict in out database
            if bool(account):
                msg = 'Failure: Account already exists!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Failure: Username must contain only characters and numbers!'
            elif not re.match(r'[0-9]+', two_factor_auth):
                msg = 'Failure: Enter phone number for 2fa'
            elif not username or not password:
                msg = 'Failure: Please fill out the form!'
            else:
                # Account doesn't exists and the form data is valid, now insert new account into dict
                # Hash password
                hashedPassword = hashlib.md5(password.encode('utf-8')).hexdigest()
                accounts[username] = {
                    'password': hashedPassword,
                    'two_factor_auth': two_factor_auth
                }
                msg = 'Success!'
        elif request.method == 'POST':
            # Form is empty... (no POST data)
            msg = 'Failure: Please fill out the form!'
        # Show registration form with message (if any)
        return render_template('register.html', msg=msg)

    # http://localhost:5000/spell_check - this will be the home page, only accessible for loggedin users
    @app.route('/spell_check', methods=['GET', 'POST'])
    def spell_check():
        msg = ''
        inputtext = ''
        # Check if user is loggedin
        if 'logged_in' in session:
            if request.method == 'POST' and 'inputtext' in request.form:
                inputtext = request.form['inputtext']
                # Put inputtext into file
                f = open('input.txt', 'w')
                f.write(inputtext)
                f.close()
                output = subprocess.getoutput('./spell_check input.txt wordlist.txt')
                msg = ', '.join(output.split())
            # User is loggedin show them the home page
            return render_template('spell_check.html', msg=msg, output=inputtext)
        # User is not loggedin redirect to login page
        return redirect(url_for('login'))

    return app