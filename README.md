# Secure Cloud Storage

A Flask web app for storing files securely. Built to practice real security features: safe password storage, email verification, MFA and encrypted file storage.

## Features

- [x] User registration and login
- [x] Password hashing with bcrypt (salted)
- [x] Session cookies with HttpOnly and SameSite flags
- [x] Parameterized SQL queries (SQL injection protection)
- [x] Email verification (in progress)
- [x] Forgot password with expiring links
- [x] OTP email MFA and authenticator app (QR) MFA
- [x] AES-256 file encryption before storage
- [x] File upload validation and size limits
- [ ] Admin/user roles, file versioning, activity logs

## Tech Stack

Python, Flask, SQLite, bcrypt, cryptography, pyotp

## Run Locally

1. Clone the repo and open the folder
2. Create the environment: `python -m venv venv`
3. Activate it: `venv\Scripts\activate`
4. Install packages: `pip install -r requirements.txt`
5. Create a `.env` file with: `SECRET_KEY=your-long-random-key`
6. Run: `python app.py`
7. Open http://127.0.0.1:5000

## Security Notes

- Secrets are stored in `.env` and never committed
- Same error message for wrong email or wrong password (prevents user enumeration)
- Known gaps being added: CSRF protection and login rate limiting

## Author

Sneha Yelpulwar, B.Tech CSE, cybersecurity enthusiast
