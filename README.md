# File Integrity Verification System

A tiny M.Sc. IT project built with Python Flask and PostgreSQL. The system uploads files, generates SHA-256 hashes, stores file metadata, and verifies whether a stored file has been modified.

## Features

- User registration and login
- Secure password hashing using Werkzeug
- File upload with a 16 MB limit
- SHA-256 hash generation
- PostgreSQL metadata storage
- File integrity verification
- File download and deletion
- User activity/audit log
- Bootstrap-based responsive interface

## Technology Stack

- Python 3.11+
- Flask
- Flask-SQLAlchemy
- PostgreSQL
- Flask-Login
- Bootstrap 5
- hashlib / SHA-256

## Project Structure

```text
file-integrity-verification/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── templates/
├── static/
│   ├── css/
│   └── js/
├── models/
├── uploads/
├── screenshots/
└── documentation/
```

## Database Setup

Create a PostgreSQL database:

```sql
CREATE DATABASE file_integrity_db;
```

Update `.env` using `.env.example`, then install dependencies:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

Set environment variables.

Windows PowerShell example:

```powershell
$env:SECRET_KEY="replace-with-a-long-random-secret"
$env:DATABASE_URL="postgresql+psycopg2://postgres:password@localhost/file_integrity_db"
```

Run:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## How Verification Works

When a file is uploaded, the application reads the file in 1 MB blocks and calculates its SHA-256 digest. The digest is stored with the file metadata. During verification, the file is hashed again. If the new digest equals the stored digest, the file is considered unchanged. If it differs, the system reports a modification.

## Security Notes

- Do not commit `.env` or real database passwords.
- Use a strong `SECRET_KEY`.
- Do not store uploaded files in a public static directory.
- For production deployment, disable Flask debug mode and use a production WSGI server.
- SHA-256 is used here for integrity verification, not password storage.
