import os
from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps
from datetime import datetime
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------- Models ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number_received = db.Column(db.String(50))
    book_number = db.Column(db.String(100))
    date_book = db.Column(db.String(50))
    date_received = db.Column(db.String(50))
    from_department = db.Column(db.String(255))
    subject = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    responsible_group = db.Column(db.String(255))
    status = db.Column(db.String(255))
    remark = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Helpers ----------------
def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in app.config['ALLOWED_EXTENSIONS']

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('ต้องเป็นผู้ดูแลระบบเท่านั้น', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- Routes ----------------
@app.route('/')
@login_required
def index():
    documents = Document.query.order_by(Document.uploaded_at.desc()).all()
    return render_template('index.html', documents=documents)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('ไม่พบไฟล์แนบ', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash('ประเภทไฟล์ไม่รองรับ', 'danger')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        doc = Document(
            number_received=request.form.get('number_received'),
            book_number=request.form.get('book_number'),
            date_book=request.form.get('date_book'),
            date_received=request.form.get('date_received'),
            from_department=request.form.get('from_department'),
            subject=request.form.get('subject'),
            file_path=filename,
            responsible_group=request.form.get('responsible_group'),
            status=request.form.get('status'),
            remark=request.form.get('remark')
        )
        db.session.add(doc)
        db.session.commit()
        flash('อัปโหลดสำเร็จ', 'success')
        return redirect(url_for('index'))

    return render_template('upload.html')

@app.route('/view/<int:doc_id>')
@login_required
def view_file(doc_id):
    document = Document.query.get_or_404(doc_id)
    return render_template('view.html', document=document)

@app.route('/files/<filename>')
@login_required
def serve_file(filename):
    safe_name = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_name)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('เข้าสู่ระบบสำเร็จ', 'success')
            return redirect(url_for('index'))
        flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ออกจากระบบแล้ว', 'info')
    return redirect(url_for('login'))

@app.route('/users')
@admin_only
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

# ---------------- Main ----------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    app.run(host='0.0.0.0', port=5000, debug=False)
