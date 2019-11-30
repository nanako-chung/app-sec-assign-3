from flask import Flask, render_template, request, redirect, url_for, session
from flask_paranoid import Paranoid
from flask_login import LoginManager, UserMixin, login_user, current_user
from flask_wtf.csrf import CSRFProtect
from database import init_db
from database import db_session
from models import Account, SpellCheck, Log
import bcrypt
import re
import subprocess
import os
import errno
import time

csrf = CSRFProtect()
init_db()

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
			hashedPassword = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
			two_factor_auth = request.form['two_factor_auth']

			# Check if account exists
			account = Account.query.filter(Account.username == username).first()
			if account is not None and bcrypt.hashpw(account.password, hashedPassword):
				if str(account.two_factor_auth) == two_factor_auth:
					# Account exists in our database
					# Create session data, we can access this data in other routes
					session['username'] = username
					session['login_time'] = time.time()
					login_user(User(username))
					new_login = Log(session['username'], session['login_time'], 'N/A')
					db_session.add(new_login)
					db_session.commit()
					msg = 'Success!'
				else:
					msg = 'Failure: Incorrect two-factor authentication'
			else:
				# Account doesn't exist or username/password incorrect
				msg = 'Failure: Incorrect username or password'
		elif request.method == 'POST':
			# Form is empty... (no POST data)
			msg = 'Failure: Please fill out the form!'

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
			hashedPassword = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
			two_factor_auth = request.form['two_factor_auth']

			# If account exists in accounts dict in out database
			if Account.query.filter(Account.username == username).first():
				msg = 'Failure: Account already exists!'
			elif not re.match(r'[A-Za-z0-9]+', username):
				msg = 'Failure: Username must contain only characters and numbers!'
			elif not re.match(r'[0-9]+', two_factor_auth):
				msg = 'Failure: Enter phone number for 2fa'
			elif not username or not password:
				msg = 'Failure: Please fill out the form!'
			else:
				# Account doesn't exists and the form data is valid, now insert new account into db
				# Insert a Account in the accounts table
				new_account = Account(username, hashedPassword, two_factor_auth)
				db_session.add(new_account)
				db_session.commit()

				user_path = './templates/' + username
				try:
					os.makedirs(user_path)
					f = open(user_path + '/history.html', 'w')
					f.write("""
<!DOCTYPE html>
<html>
	<head>
		<meta charset='utf-8'>
		<title>History</title>
	</head>
	<body>
		<h1>History</h1>
		<span class='numqueries' id='numqueries'>{{ numqueries }}</span> queries performed before:</br></br>
		{%- for num, spell_check in spell_checks %}
			<div>{{ num }}. <a id="query{{ num }}" href="{{ url_for('query', query_id=num) }}">{{ spell_check.submitted_text }}</a></div>
		{%- endfor %}
		<input type='hidden' name='csrf_token' value='{{ csrf_token() }}'/></br></br>
		<a href="{{ url_for('logout') }}">Logout</a>
	</body>
</html>""")
					f.close()
					f = open(user_path + '/login_history.html', 'w')
					f.write("""
<!DOCTYPE html>
<html>
	<head>
		<meta charset='utf-8'>
		<title>Login History</title>
	</head>
	<body>
		<h1>Login History</h1>
		{%- for num, log in logs %}
			<div>Session {{ num }} login time: <span id="login{{ num }}_time">{{ log.login_time }}</span></div>
			<div>Session {{ num }} logout time: <span id="logout{{ num }}_time">{{ log.logout_time }}</span></div>
		{%- endfor %}
		<input type='hidden' name='csrf_token' value='{{ csrf_token() }}'/></br></br>
	</body>
</html>""")
					f.close()
				except OSError as exc: # Guard against race condition
					if exc.errno != errno.EEXIST:
						raise

				msg = 'Success!'
		elif request.method == 'POST':
			# Form is empty... (no POST data)
			msg = 'Failure: Please fill out the form!'

		# Show registration form with message (if any)
		return render_template('register.html', msg=msg)

	# http://localhost:5000/spell_check - this will be the home page, only accessible for loggedin users
	@app.route('/spell_check', methods=['GET', 'POST'])
	def spell_check():
		# Check if user is loggedin
		if 'username' not in session:
			# User is not loggedin redirect to login page
			return redirect(url_for('login'))

		msg = ''
		inputtext = ''
		if request.method == 'POST' and 'inputtext' in request.form:
			inputtext = request.form['inputtext']
			# Put inputtext into file
			f = open('input.txt', 'w')
			f.write(inputtext)
			f.close()
			output = subprocess.getoutput('./spell_check input.txt wordlist.txt')
			msg = ', '.join(output.split())

			spell_check = SpellCheck(session['username'], inputtext, msg)
			db_session.add(spell_check)
			db_session.commit()

			user_path = './templates/' + session['username']
			query_num = str(SpellCheck.query.filter(SpellCheck.account_username == session['username']).count())
			f = open(user_path + '/query' + query_num + '.html', 'w')
			f.write("""
<!DOCTYPE html>
<html>
	<head>
		<meta charset='utf-8'>
		<title>Query {}</title>
	</head>
	<body>
		<h1>Query {}</h1>
		<div>Query number: <span id="queryid">{}</span></div>
		<div>Username: <span id="username">{}</span></div>
		<div>Query text: <span id="querytext">{}</span></div>
		<div>Query results: <span id="queryresults">{}</span></div>
	</body>
</html>""".format(query_num, query_num, query_num, session['username'], inputtext, msg))
			f.close()

		# User is loggedin show them the spell_check page
		return render_template('spell_check.html', msg=msg, output=inputtext)

	# http://localhost:5000/history - this will be the history of all queries run
	@app.route('/history', methods=['GET', 'POST'])
	def history():
		# Check if user is loggedin
		if 'username' not in session:
			# User is not loggedin redirect to login page
			return redirect(url_for('login'))

		# if session['username'] == 'admin':
		# 	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'two_factor_auth' in request.form:
		# 		# Create variables for easy access
		# 		username = request.form['username']

		# User is loggedin show them the home page
		return render_template('/' + session['username'] + '/history.html', numqueries=SpellCheck.query.filter(SpellCheck.account_username == session['username']).count(), spell_checks=list(enumerate(SpellCheck.query.filter(SpellCheck.account_username == session['username']).all(), 1)))

	# http://localhost:5000/history/query# - this will give the user info about a specific query
	@app.route('/history/query<int:query_id>', methods=['GET', 'POST'])
	def query(query_id):
		# Check if user is loggedin
		if 'username' not in session:

			# User is not loggedin redirect to login page
			return redirect(url_for('login'))

		# User is loggedin show them the home page
		return render_template(session['username'] + '/query' + str(query_id) + '.html')

	# http://localhost:5000/login_history - this will be the history of all queries run
	@app.route('/login_history', methods=['GET', 'POST'])
	def login_history():
		# Check if user is loggedin
		if 'username' not in session:
			# User is not loggedin redirect to login page
			return redirect(url_for('login'))

		# User is loggedin show them the home page
		return render_template('/' + session['username'] + '/login_history.html', logs=list(enumerate(Log.query.filter(Log.account_username == session['username']).all(), 1)))
	
	# http://localhost:5000/logout - this will be the logout page, we need to use both GET and POST requests
	@app.route('/logout')
	def logout():
		log = Log.query.filter(Log.account_username == session['username']).filter(Log.login_time == session['login_time']).first()
		log.logout_time = time.time()
		db_session.add(log)
		db_session.commit()
		
		# remove the username from the session if it is there
		session.pop('username', None)
		session.pop('login_time', None)
		return redirect(url_for('login'))

	return app