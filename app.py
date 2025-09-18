from werkzeug.security import generate_password_hash
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt
)
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
from flask import send_from_directory

import os, re, secrets, logging # loging For testing tasks---
from config import Config
from moduler import db, User, RevokedToken, Appointment, File

# Setup logging
logging.basicConfig(level=logging.INFO)

def is_valid_username(username):
    # Only allow letters, numbers, underscores
    return re.match(r'^\w+$', username)

def is_valid_email(email):
    # Basic email pattern
    return re.match(r'[^@]+@[^@]+\.[^@]+', email)

#------------------ App Setup ------------------
app = Flask(__name__)
app.config.from_object(Config)

#JWT config
app.config['JWT_SECRET_KEY'] = 'supersecretjwt'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

#Secret ey for Sessions Reset Token
app.config['SECRET_KEY'] = 'supersecretkeyforflask'
from itsdangerous import URLSafeTimedSerializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
jwt = JWTManager(app)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#Lager tabeller 
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@example.com").first():
        admin_user = User(
            username="admin",
            email="admin@example.com",
            password=bcrypt.generate_password_hash("AdminPassword123").decode("utf-8"),
            role="admin"
        )
        db.session.add(admin_user)
        db.session.commit()

# Admin role decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != "admin":
            flash("Unauthorized access", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------ HTML Routes ------------------

# Register route updated for testing porpuses but the logic remains the same
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Input validation
        if not username or not email or not password:
            flash("All fields are required!", "ERROR")
            return redirect(url_for("register"))

        if not is_valid_username(username):
            logging.warning(f"Invalid username attempt blocked: {username}")
            flash("Invalid username.", "ERROR")
            return redirect(url_for("register"))

        if not is_valid_email(email):
            logging.warning(f"Invalid email attempt blocked: {email}")
            flash("Invalid email.", "ERROR")
            return redirect(url_for("register"))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists!", "ERROR")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash("Account has been created successfully!", "SUCCESS")
        return redirect(url_for("login"))

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))
        else:
            flash("Login failed. Check email and password.", "ERROR")
    return render_template("login.html")


#Reset-Request-password app route
@app.route("/reset_password", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt="password-reset-salt")
            reset_link = url_for("reset_token", token=token, _external=True)
            # TODO: send `reset_link` via email
            flash(f"A password reset link has been sent to {email}!", "info")
        else:
            flash("Email not found.", "error")
        return redirect(url_for("login"))
    return render_template("reset_password_request.html")

#Password-Reset_Token-Rout
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=3600)  # 1 hour expiry
    except Exception:
        flash("The reset link is invalid or has expired.", "error")
        return redirect(url_for("reset_request"))

    user = User.query.filter_by(email=email).first()
    if request.method == "POST":
        new_password = request.form.get("password")
        if not new_password:
            flash("Please enter a new password.", "error")
            return redirect(request.url)
        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.password = hashed_pw
        db.session.commit()
        flash("Your password has been updated! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

# ------------------ Admin Dashboard ------------------
@app.route("/admin", methods=["GET", "POST"])
@login_required
@admin_required
def admin_dashboard():
    users = User.query.filter(User.role != "admin").all()
    appointments = Appointment.query.all()

    if request.method == "POST":
        user_id = request.form.get("user_id")
        file = request.files.get("file")

        if not user_id:
            flash("Please select a user.", "error")
            return redirect(url_for("admin_dashboard"))

        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("admin_dashboard"))

        if not allowed_file(file.filename):
            flash("File type not allowed.", "error")
            return redirect(url_for("admin_dashboard"))

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        new_file = File(
            filename=filename,
            filepath=filepath,
            uploaded_by=current_user.id,
            user_id=user_id
        )
        db.session.add(new_file)
        db.session.commit()

        flash("File uploaded successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_dashboard.html", users=users, appointments=appointments)


# ------------------ Patient Dashboard ------------------
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    message = ""
    if request.method == "POST":
        date_str = request.form.get("date")
        time_str = request.form.get("time")
        appointment_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        appointment_time = datetime.strptime(time_str, "%H:%M").time()

        new_appointment = Appointment(
            patient_id=current_user.id,
            date=appointment_date,
            time=appointment_time
        )
        db.session.add(new_appointment)
        db.session.commit()

        message = f"Appointment booked for {date_str} at {time_str}!"

    upcoming_appointments = Appointment.query.filter_by(patient_id=current_user.id).order_by(Appointment.date, Appointment.time).all()

    return render_template("dasboard.html", 
                           name=current_user.username, 
                           message=message, 
                           appointments=upcoming_appointments)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ------------------ API (Tokenbased) ------------------
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    if not data or not re.match(r'^\w+$', data.get('username', '')):
        return jsonify({"error": "Invalid username"}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", data.get('email', '')):
        return jsonify({"error": "Invalid email"}), 400
    if len(data.get('password', '')) < 6:
        return jsonify({"error": "Password too short"}), 400

    if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
        return jsonify({"error": "Username or email already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created"}), 201

#endpint for login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not bcrypt.check_password_hash(user.password, data.get('password')):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=user.id)
    return jsonify(access_token=token), 200

#Endpoint for Logout
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def api_logout():
    jti = get_jwt()['jti']
    db.session.add(RevokedToken(jti=jti))
    db.session.commit()
    return jsonify({"message": "Token revoked"}), 200


@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti'] #identify the token individually
    return RevokedToken.query.filter_by(jti=jti).first() is not None #Checks if the token is revoked


@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def api_dashboard():
    return jsonify({"message": "Welcome to the protected dashboard!"})





#---------Test Driven Development--------------#

import hashlib

class AuthSystem:
    def __init__(self):
        self.users = {}  # Store the users in a dictionary

    def register(self, username, password, role="user"):
    # Store password as a SHA-256 hash
        self.users[username] = {
            "hash": hashlib.sha256(password.encode()).hexdigest(),
            "role": role
        }

    def login(self, username, password):
        user = self.users.get(username)
        if not user:
            return False
        return user["hash"] == hashlib.sha256(password.encode()).hexdigest()

    def is_admin(self, username):
        return self.users.get(username, {}).get("role") == "admin"



if __name__ == "__main__":
    app.run(debug=True)
