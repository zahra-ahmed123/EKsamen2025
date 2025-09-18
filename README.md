Hospital Management System (HMS)
Overview
This project is a Hospital Management System (HMS) built using Python and Flask.

Features
•	User Authentication
o	Secure registration and login with password hashing
o	Role-based access control (Admin and Patient)
•	Admin
o	Upload and manage files securely
o	View all patients
•	Patient
o	Book appointments
o	View their own data
•	Security
o	Password reset mechanism using secure tokens
o	Session-based authentication
o	Encrypted password storage
•	API
o	Secure RESTful API endpoints protected with authentication and authorization
•	File Handling
o	Secure file upload/download with role-based restrictions (only admins can upload)

Technology 
Backend: Flask (Python)
•	Database: SQLite (via SQLAlchemy ORM)
•	Frontend: HTML / CSS / Jinja templates
•	Security: Werkzeug for password hashing
 
Getting Started
1. Clone the repository
git clone <https://github.com/zahra-ahmed123/EKsamen2025>
cd A.3
2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate
3. Install dependencies
pip install -r requirements.txt
4. Initialize the database
5. Create an admin user
python
>>> from app import create_app, db
>>> from app.models import User
>>> from app.utils.security import hash_password
>>> app = create_app()
>>> with app.app_context():
...     admin = User(email="admin@example.com", password_hash=hash_password("AdminPass123"), role="admin")
...     db.session.add(admin)
...     db.session.commit()
6. Run the application
python run.py
Open the app at: http://localhost:5000/register 

 Notes
Only admins can upload files.
Only patients can book appointments
All sensitive data is protected using secure coding practices and role-based access.
License
This project is created for educational purposes. All rights reserved.

