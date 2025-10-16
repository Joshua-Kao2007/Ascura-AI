from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os
import time, random

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

Welcome to Ascura!

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
        city = request.form['city']
        if city == 'Other':
            city = request.form['other_city']

        # --- duplicate checks ---
        if users_collection.find_one({'username': username}):
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        if users_collection.find_one({'email': email}):
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        # --- hash password and insert user ---
        hashed_pw = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pw,
            'city': city,
            'verified': False
        })

        # --- generate and send verification code ---
        code = str(random.randint(100000, 999999))
        expiry = time.time() + 600  # 10 minutes
        users_collection.update_one(
            {'email': email},
            {'$set': {'verify_code': code, 'code_expiry': expiry}}
        )

        msg = Message(
            'Your Verification Code',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = (
            f"Hi {username},\n\n"
            f"Your verification code is: {code}\n"
            f"This code will expire in 10 minutes.\n\n"
            f"Thank you for registering!"
        )
        mail.send(msg)

        flash('Registration successful! Please check your email for a 6-digit verification code.', 'info')
        session['pending_email'] = email
        return redirect(url_for('verify_code'))

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


@app.route('/verify', methods=['GET', 'POST'])
def verify_code():
    email = session.get('pending_email')
    if not email:
        flash('No pending verification. Please register or log in first.', 'warning')
        return redirect(url_for('register'))

    if request.method == 'POST':
        code = request.form['code']
        user = users_collection.find_one({'email': email})

        if not user:
            flash('No account found for verification.', 'danger')
            return redirect(url_for('register'))

        if time.time() > user.get('code_expiry', 0):
            flash('Verification code expired. Please request a new one.', 'warning')
            return redirect(url_for('resend_verification'))

        if user.get('verify_code') == code:
            users_collection.update_one({'email': email}, {
                '$set': {'verified': True},
                '$unset': {'verify_code': '', 'code_expiry': ''}
            })
            session.pop('pending_email', None)
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid code. Please try again.', 'danger')

    return render_template('verify.html', title='Verify Email')

@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    email = session.get('pending_email')
    if not email:
        flash('No pending verification email found.', 'warning')
        return redirect(url_for('register'))

    user = users_collection.find_one({'email': email})
    if not user:
        flash('No account found for that email.', 'danger')
        return redirect(url_for('register'))

    if user.get('verified', False):
        flash('This account is already verified. Please log in.', 'info')
        return redirect(url_for('login'))

    # Cooldown check
    last_sent = user.get('last_code_sent', 0)
    cooldown = 60
    if time.time() - last_sent < cooldown:
        wait = int(cooldown - (time.time() - last_sent))
        flash(f'Please wait {wait} seconds before requesting another code.', 'warning')
        return redirect(url_for('verify_code'))

    # New code
    code = str(random.randint(100000, 999999))
    expiry = time.time() + 600
    users_collection.update_one(
        {'email': email},
        {'$set': {'verify_code': code, 'code_expiry': expiry, 'last_code_sent': time.time()}}
    )

    msg = Message('Your New Verification Code',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"Your new verification code is: {code}\nIt expires in 10 minutes."
    mail.send(msg)

    flash('A new verification code has been sent to your email.', 'info')
    return redirect(url_for('verify_code'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip().lower()
        password = request.form['password']

        user = users_collection.find_one({
            '$or': [{'email': identifier}, {'username': identifier}]
        })

        if user and check_password_hash(user['password'], password):
            if not user.get('verified', False):
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('verify_code'))
            
            session['username'] = user['username']
            flash(f'Welcome back, {user["username"]}!', 'success')
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
