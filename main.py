from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os

# -------------------- LOAD ENVIRONMENT VARIABLES --------------------
load_dotenv()  # must come before any os.getenv()

# -------------------- FLASK APP SETUP --------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# -------------------- MONGO DB CONNECTION --------------------
uri = os.getenv("MONGO_URI")
client = MongoClient(uri, server_api=ServerApi('1'))
db = client["Social_Media_App"]
users_collection = db["users"]

# -------------------- MAIL CONFIG --------------------
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("EMAIL_USER"),
    MAIL_PASSWORD=os.getenv("EMAIL_PASS"),
)
mail = Mail(app)

# Serializer for secure email tokens
s = URLSafeTimedSerializer(app.secret_key)


# -------------------- HELPER FUNCTION --------------------
def send_verification_email(email, username):
    """Send email verification link."""
    token = s.dumps(email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg = Message('Confirm Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"""
Hi {username},

Welcome to Social Media App!

Please verify your email by clicking the link below:
{confirm_url}

This link expires in 1 hour.

If you did not register, please ignore this email.
"""
    mail.send(msg)


# -------------------- ROUTES --------------------

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email'].lower()
        password = request.form['password']

        if users_collection.find_one({'username': username}):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if users_collection.find_one({'email': email}):
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pw,
            'verified': False
        })

        send_verification_email(email, username)
        flash('Registration successful! Please check your email to verify your account.', 'info')
        return redirect(url_for('login'))

    return render_template('register.html', title='Register')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('The verification link has expired. Please request a new one.', 'warning')
        return redirect(url_for('resend_verification'))
    except BadSignature:
        flash('Invalid or tampered verification link.', 'danger')
        return redirect(url_for('login'))

    user = users_collection.find_one({'email': email})
    if user and not user.get('verified'):
        users_collection.update_one({'email': email}, {'$set': {'verified': True}})
        flash('Email verified successfully! You can now log in.', 'success')
    else:
        flash('This email is already verified or invalid.', 'info')

    return redirect(url_for('login'))


@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form['email'].lower()
        user = users_collection.find_one({'email': email})
        if user:
            if user.get('verified'):
                flash('Your account is already verified. You can log in.', 'info')
                return redirect(url_for('login'))
            send_verification_email(email, user['username'])
            flash('A new verification email has been sent!', 'success')
        else:
            flash('No account found with that email.', 'danger')
        return redirect(url_for('login'))
    return render_template('resend_verification.html', title='Resend Verification')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            if not user.get('verified', False):
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('resend_verification'))
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html', title='Login')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/home')
def home():
    if 'username' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    return render_template('home.html', username=session['username'], title='Home')


# -------------------- MAIN ENTRY POINT --------------------
if __name__ == '__main__':
    app.run(debug=True)
