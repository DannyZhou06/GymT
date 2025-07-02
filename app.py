# app.py
# This is the main application file for the Gym Tracker platform.

import os
import secrets
from PIL import Image
import io
from flask import Flask, render_template, redirect, url_for, flash, request, make_response, send_file, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from datetime import datetime, date, timedelta
import calendar
from functools import wraps
from sqlalchemy import func
# from weasyprint import HTML # PDF functionality disabled
import pandas as pd
from wtforms import validators
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer

# Import the database, models, and forms
from models import db, User, Attendance
from forms import LoginForm, UserForm, ChangePasswordForm, RequestResetForm, ResetPasswordForm

# --- App Configuration ---

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-and-secure-key-for-development')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

# **CHANGE:** Use the DATABASE_URL from Render's environment, with a local fallback
# This makes the app connect to your Neon database when deployed.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///instance/gym_tracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# --- Decorators ---

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role_name:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_or_trainer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'trainer']:
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- User Loader for Flask-Login ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    if not os.path.exists(os.path.join(app.root_path, 'static/profile_pics')):
        os.makedirs(os.path.join(app.root_path, 'static/profile_pics'))
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

def get_calendar_data(user_id, year, month):
    cal = calendar.Calendar()
    month_days = cal.itermonthdates(year, month)
    start_of_month = date(year, month, 1)
    end_of_month = date(year, month, calendar.monthrange(year, month)[1])
    attendance_records = Attendance.query.filter(
        Attendance.user_id == user_id,
        Attendance.check_in_timestamp >= start_of_month,
        Attendance.check_in_timestamp <= end_of_month
    ).all()
    attended_dates = {record.check_in_timestamp.date() for record in attendance_records}
    calendar_days = []
    today = date.today()
    for day in month_days:
        if day.month == month:
            calendar_days.append({
                "number": day.day, "date_str": day.isoformat(),
                "attended": day in attended_dates, "is_today": day == today
            })
        else:
            calendar_days.append({"number": 0, "date_str": None, "attended": False, "is_today": False})
    return calendar_days

# --- Main Routes ---

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)
    session.modified = True

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if user.is_active:
                login_user(user)
                session.permanent = True
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('This account is inactive. Please contact an administrator.', 'error')
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'member':
        return redirect(url_for('member_dashboard'))
    elif current_user.role == 'trainer':
        return redirect(url_for('trainer_dashboard'))
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# --- Account Management Routes ---

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Your password has been updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect old password.', 'error')
    return render_template('change_password.html', form=form)

def get_reset_token(user):
    s = Serializer(app.config['SECRET_KEY'])
    return s.dumps({'user_id': user.id})

def verify_reset_token(token, expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token, max_age=expires_sec)['user_id']
    except:
        return None
    return User.query.get(user_id)

@app.route('/reset_password', methods=['GET', 'POST'])
def request_reset():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = get_reset_token(user)
            reset_link = url_for('reset_token', token=token, _external=True)
            print(f"--- PASSWORD RESET LINK for {user.email} ---")
            print(reset_link)
            print("-------------------------------------------------------------")
            flash('A password reset link has been generated. For now, check the server console.', 'info')
        else:
            flash('No account found with that email address.', 'warning')
    return render_template('request_reset.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    user = verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token.', 'warning')
        return redirect(url_for('request_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# --- Member Routes ---

@app.route('/member/dashboard')
@login_required
@role_required('member')
def member_dashboard():
    today = datetime.utcnow().date()
    start_of_month = today.replace(day=1)
    visits_this_month = Attendance.query.filter(Attendance.user_id == current_user.id, func.date(Attendance.check_in_timestamp) >= start_of_month).count()
    trainer_name = current_user.trainer.full_name if current_user.trainer else None
    calendar_title = today.strftime("%B %Y")
    calendar_days = get_calendar_data(current_user.id, today.year, today.month)
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('member_dashboard.html', image_file=image_file, visits_this_month=visits_this_month, trainer_name=trainer_name, calendar_title=calendar_title, calendar_days=calendar_days)

# --- Trainer & Admin Shared Routes ---

@app.route('/mark_attendance/<int:member_id>', methods=['GET', 'POST'])
@login_required
@admin_or_trainer_required
def mark_attendance(member_id):
    member = User.query.get_or_404(member_id)
    if member.role != 'member':
        flash('You can only mark attendance for members.', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        date_str = request.form.get('attendance_date')
        if date_str:
            attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            already_checked_in = Attendance.query.filter(
                Attendance.user_id == member.id,
                func.date(Attendance.check_in_timestamp) == attendance_date
            ).first()
            if not already_checked_in:
                new_attendance = Attendance(user_id=member.id, check_in_timestamp=datetime.combine(attendance_date, datetime.min.time()))
                db.session.add(new_attendance)
                db.session.commit()
                flash(f"Attendance marked for {member.full_name} on {date_str}.", "success")
            else:
                flash(f"{member.full_name} was already marked present on {date_str}.", "info")
        else:
            flash("Please select a date.", "error")
        return redirect(url_for('mark_attendance', member_id=member_id))
    today_str = date.today().isoformat()
    return render_template('mark_attendance.html', member=member, today_str=today_str)

# --- Trainer Routes ---

@app.route('/trainer/dashboard')
@login_required
@role_required('trainer')
def trainer_dashboard():
    clients = current_user.assigned_members.filter_by(is_active=True).all()
    today = datetime.utcnow().date()
    start_of_month = today.replace(day=1)
    for client in clients:
        last_check_in_record = Attendance.query.filter_by(user_id=client.id).order_by(Attendance.check_in_timestamp.desc()).first()
        client.last_check_in = last_check_in_record.check_in_timestamp if last_check_in_record else None
        client.visits_this_month = Attendance.query.filter(
            Attendance.user_id == client.id,
            func.date(Attendance.check_in_timestamp) >= start_of_month
        ).count()
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('trainer_dashboard.html', clients=clients, image_file=image_file)

# --- Admin Routes ---

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    members = User.query.filter_by(role='member').order_by(User.full_name).all()
    trainers = User.query.filter_by(role='trainer').order_by(User.full_name).all()
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('admin_dashboard.html', members=members, trainers=trainers, image_file=image_file)

@app.route('/admin/user/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    form = UserForm()
    trainers = User.query.filter_by(role='trainer').all()
    form.trainer_id.choices = [(t.id, t.full_name) for t in trainers]
    form.trainer_id.choices.insert(0, (0, 'None'))
    form.password.validators.insert(0, validators.DataRequired())
    
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'error')
            return render_template('user_form.html', form=form, title="Add New User")
        if User.query.filter_by(email=form.email.data).first():
            flash('Email address already exists.', 'error')
            return render_template('user_form.html', form=form, title="Add New User")
        
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data,
            role=form.role.data,
            is_active=form.is_active.data
        )
        new_user.set_password(form.password.data)
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            new_user.image_file = picture_file
        if new_user.role == 'member' and form.trainer_id.data != 0:
            new_user.trainer_id = form.trainer_id.data
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {new_user.full_name} created successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('user_form.html', form=form, title="Add New User")

@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    form = UserForm(obj=user_to_edit)
    trainers = User.query.filter_by(role='trainer').all()
    form.trainer_id.choices = [(t.id, t.full_name) for t in trainers]
    form.trainer_id.choices.insert(0, (0, 'None'))

    if form.validate_on_submit():
        user_to_edit.full_name = form.full_name.data
        user_to_edit.email = form.email.data
        user_to_edit.role = form.role.data
        user_to_edit.is_active = form.is_active.data
        if form.picture.data:
            user_to_edit.image_file = save_picture(form.picture.data)
        if form.password.data:
            user_to_edit.set_password(form.password.data)
        if user_to_edit.role == 'member':
            user_to_edit.trainer_id = form.trainer_id.data if form.trainer_id.data != 0 else None
        else:
            user_to_edit.trainer_id = None
        db.session.commit()
        flash(f'User {user_to_edit.full_name} updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'GET':
        form.trainer_id.data = user_to_edit.trainer_id or 0
        form.is_active.data = user_to_edit.is_active
    image_file = url_for('static', filename='profile_pics/' + user_to_edit.image_file)
    return render_template('user_form.html', form=form, title=f"Edit {user_to_edit.full_name}", image_file=image_file)

@app.route('/admin/report/excel')
@login_required
@role_required('admin')
def download_excel_report():
    today = datetime.utcnow().date()
    start_of_month = today.replace(day=1)
    query = db.session.query(
        User.full_name,
        User.email,
        func.date(Attendance.check_in_timestamp).label('check_in_date')
    ).join(Attendance, User.id == Attendance.user_id).filter(
        func.date(Attendance.check_in_timestamp) >= start_of_month,
        User.role == 'member'
    ).order_by(User.full_name, 'check_in_date').all()
    df = pd.DataFrame(query, columns=['Member Name', 'Email', 'Check-in Date'])
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    df.to_excel(writer, sheet_name='Monthly_Attendance', index=False)
    writer.close()
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name=f'Attendance_Report_{today.strftime("%Y-%m")}.xlsx')

# --- CLI Commands for Database Management ---

@app.cli.command("create-admin")
def create_admin_command():
    with app.app_context():
        admin_username = 'admin'
        if User.query.filter_by(username=admin_username).first():
            print("Admin user already exists.")
            return
        admin = User(username=admin_username, email='admin@example.com', full_name='Admin User', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user '{admin_username}' created successfully.")
