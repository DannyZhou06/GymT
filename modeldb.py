# models.py
# This file defines the database structure for our application.

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize the database extension
db = SQLAlchemy()

# --- Database Models ---

class User(db.Model, UserMixin):
    """
    Represents a user in the system.
    This single model handles Members, Trainers, and Administrators,
    differentiated by the 'role' field.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    # Username is now the primary identifier for login
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member') # 'member', 'trainer', 'admin'
    
    # Field for profile picture filename
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # --- Relationships ---
    
    assigned_members = db.relationship('User', backref=db.backref('trainer', remote_side=[id]), lazy='dynamic',
                                       foreign_keys='User.trainer_id')
    
    trainer_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    attendance_records = db.relationship('Attendance', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        """Creates a hashed password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Attendance(db.Model):
    """
    Represents a single gym check-in for a member.
    """
    __tablename__ = 'attendance'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    check_in_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        formatted_time = self.check_in_timestamp.strftime('%Y-%m-%d @ %H:%M')
        return f'<Attendance record for user {self.user_id} on {formatted_time}>'
