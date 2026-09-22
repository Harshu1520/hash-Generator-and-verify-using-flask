import os
import hashlib
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///file_integrity.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    files = db.relationship("FileRecord", backref="owner", lazy=True, cascade="all, delete-orphan")
    activities = db.relationship("ActivityLog", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class FileRecord(db.Model):
    __tablename__ = "file_records"
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(block)
    return sha256.hexdigest()


def log_activity(action, details):
    db.session.add(ActivityLog(action=action, details=details, user_id=current_user.id))
    db.session.commit()


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "danger")
            return render_template("register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "warning")
            return render_template("register.html")

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    records = FileRecord.query.filter_by(owner_id=current_user.id).order_by(FileRecord.uploaded_at.desc()).all()
    activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(10).all()
    return render_template("dashboard.html", records=records, activities=activities)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")

        if not file or not file.filename:
            flash("Please select a file.", "danger")
            return render_template("upload.html")

        original = secure_filename(file.filename)
        if not original:
            flash("Invalid filename.", "danger")
            return render_template("upload.html")

        # Use a unique server-side filename to avoid collisions and unsafe paths.
        stored = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{current_user.id}_{original}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
        file.save(path)

        digest = calculate_sha256(path)
        size = os.path.getsize(path)

        record = FileRecord(
            original_filename=original,
            stored_filename=stored,
            file_size=size,
            sha256_hash=digest,
            owner_id=current_user.id
        )
        db.session.add(record)
        db.session.commit()

        log_activity("FILE_UPLOADED", f"{original} | SHA-256: {digest}")
        flash("File uploaded and SHA-256 hash generated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")


@app.route("/verify/<int:file_id>", methods=["GET", "POST"])
@login_required
def verify(file_id):
    record = FileRecord.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    path = os.path.join(app.config["UPLOAD_FOLDER"], record.stored_filename)

    if not os.path.exists(path):
        flash("Stored file is missing. Verification cannot be completed.", "danger")
        return redirect(url_for("dashboard"))

    current_hash = calculate_sha256(path)
    is_valid = current_hash == record.sha256_hash

    if request.method == "POST":
        log_activity(
            "FILE_VERIFIED",
            f"{record.original_filename} | Expected: {record.sha256_hash} | Current: {current_hash} | Result: {'VALID' if is_valid else 'MODIFIED'}"
        )
        flash(
            "Integrity verified: the file matches its stored SHA-256 hash." if is_valid
            else "Integrity warning: the file hash has changed.",
            "success" if is_valid else "danger"
        )

    return render_template(
        "verify.html",
        record=record,
        current_hash=current_hash,
        is_valid=is_valid
    )


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    record = FileRecord.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        record.stored_filename,
        as_attachment=True,
        download_name=record.original_filename
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    record = FileRecord.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    path = os.path.join(app.config["UPLOAD_FOLDER"], record.stored_filename)

    if os.path.exists(path):
        os.remove(path)

    filename = record.original_filename
    db.session.delete(record)
    db.session.commit()
    log_activity("FILE_DELETED", filename)
    flash("File deleted successfully.", "info")
    return redirect(url_for("dashboard"))


@app.errorhandler(413)
def too_large(_error):
    flash("File is too large. Maximum allowed size is 16 MB.", "danger")
    return redirect(url_for("upload"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
