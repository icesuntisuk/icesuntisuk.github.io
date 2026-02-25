import os
import uuid
import secrets
import re
from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from functools import wraps
from datetime import datetime
from config import Config
from itsdangerous import URLSafeSerializer, BadSignature

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
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
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

class DocumentVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(36))
    file_path = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.String(80))

class DocumentLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.String(36))
    action = db.Column(db.String(50))
    username = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

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
    return db.session.get(User, int(user_id))

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.template_filter('user_token')
def user_token_filter(user_id):
    s = URLSafeSerializer(app.config['SECRET_KEY'], salt='user-edit')
    return s.dumps(user_id)

# ---------------- Routes ----------------
@app.route('/')
@login_required
def index():
    query = request.args.get('q', '').strip()
    search = f"%{query}%"

    if query:
        documents = Document.query.filter(
            db.or_(
                Document.subject.ilike(search),
                Document.book_number.ilike(search),
                Document.from_department.ilike(search),
                Document.date_book.ilike(search),
                Document.date_received.ilike(search),
                Document.status.ilike(search)
            )
        ).order_by(Document.uploaded_at.desc()).all()
    else:
        documents = Document.query.order_by(Document.uploaded_at.desc()).all()

    return render_template('index.html', documents=documents, query=query)


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
            date_book=convert_thai_date_to_gregorian(request.form.get('date_book')),
            date_received=convert_thai_date_to_gregorian(request.form.get('date_received')),
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



@app.route('/edit/<string:doc_id>', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if request.method == 'POST':
        version = DocumentVersion(
            document_id=doc.id,
            file_path=doc.file_path,
            updated_by=current_user.username
        )
        db.session.add(version)
        doc.number_received = request.form.get('number_received')
        doc.book_number = request.form.get('book_number')
        doc.date_book = convert_thai_date_to_gregorian(request.form.get('date_book'))
        doc.date_received = convert_thai_date_to_gregorian(request.form.get('date_received'))
        doc.from_department = request.form.get('from_department')
        doc.subject = request.form.get('subject')
        doc.responsible_group = request.form.get('responsible_group')
        doc.status = request.form.get('status')
        doc.remark = request.form.get('remark')

        file = request.files.get('file')
        if file and file.filename != '' and allowed_file(file.filename):
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.file_path)
            if os.path.exists(old_path):
                os.remove(old_path)
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)
            doc.file_path = filename

        db.session.commit()
        log = DocumentLog(document_id=doc.id, action='edit', username=current_user.username)
        db.session.add(log)
        db.session.commit()
        flash('แก้ไขเอกสารเรียบร้อยแล้ว', 'success')
        return redirect(url_for('index'))
    return render_template('edit_document.html', doc=doc)




@app.route('/delete/<string:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    path = os.path.join(app.config['UPLOAD_FOLDER'], doc.file_path)
    try:
        if os.path.exists(path):
            os.remove(path)
        log = DocumentLog(document_id=doc.id, action='delete', username=current_user.username)
        db.session.add(log)
        db.session.delete(doc)
        db.session.commit()
        flash('ลบเอกสารเรียบร้อยแล้ว', 'info')
    except Exception as e:
        flash(f'เกิดข้อผิดพลาดในการลบเอกสาร: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/view/<string:doc_id>')
@login_required
def view_file(doc_id):
    document = Document.query.get_or_404(doc_id)
    log = DocumentLog(document_id=doc_id, action='view', username=current_user.username)
    db.session.add(log)
    db.session.commit()
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

@app.route('/users', methods=['GET', 'POST'])
@admin_only
def manage_users():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('มีผู้ใช้นี้อยู่แล้ว', 'danger')
        else:
            if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[^A-Za-z0-9]", password):
                flash('รหัสผ่านไม่ปลอดภัย: ต้องมีความยาวอย่างน้อย 8 ตัวอักษร รวมตัวใหญ่ ตัวเล็ก ตัวเลข และอักขระพิเศษ', 'danger')
                return redirect(url_for('manage_users'))
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('เพิ่มผู้ใช้เรียบร้อยแล้ว', 'success')
        return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/users/edit/<string:token>', methods=['GET', 'POST'])
@admin_only
def edit_user(token):
    s = URLSafeSerializer(app.config['SECRET_KEY'], salt='user-edit')
    try:
        user_id = s.loads(token)
    except BadSignature:
        flash('ลิงก์ไม่ถูกต้องหรือหมดอายุ', 'danger')
        return redirect(url_for('manage_users'))

    try:
        user = db.session.execute(db.select(User).filter_by(id=user_id)).scalar_one()
    except Exception:
        flash('ไม่พบผู้ใช้ที่ระบุ', 'danger')
        return redirect(url_for('manage_users'))

    if request.method == 'POST':
        role = request.form['role']
        password = request.form['password']

        if role not in ['admin', 'user']:
            flash('บทบาทไม่ถูกต้อง', 'danger')
            return redirect(url_for('edit_user', token=token))

        user.role = role

        if password:
            if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[^A-Za-z0-9]", password):
                flash('รหัสผ่านไม่ปลอดภัย: ต้องมีความยาวอย่างน้อย 8 ตัวอักษร รวมตัวใหญ่ ตัวเล็ก ตัวเลข และอักขระพิเศษ', 'danger')
                return redirect(url_for('edit_user', token=token))
            user.set_password(password)

        db.session.commit()
        flash('อัปเดตข้อมูลผู้ใช้เรียบร้อยแล้ว', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:user_id>')
@admin_only
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('ไม่พบผู้ใช้', 'danger')
    elif user.username == 'admin':
        flash('ไม่สามารถลบ admin หลักได้', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('ลบผู้ใช้แล้ว', 'info')
    return redirect(url_for('manage_users'))


def convert_thai_date_to_gregorian(date_str):
    try:
        day, month, year = map(int, date_str.split('-'))
        year -= 543  # แปลง พ.ศ. → ค.ศ.
        return f"{year:04d}-{month:02d}-{day:02d}"
    except Exception:
        return ''

# ---------------- Main ----------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
        random_password = secrets.token_urlsafe(12)
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', role='admin')
            db.session.add(admin)
        admin.set_password(random_password)
        db.session.commit()
        with open("admin_password.txt", "w") as f:
            f.write("🔐 Username: admin\n")
            f.write(f"🔑 Password: {random_password}\n")
            f.write("⚠️  โปรดเปลี่ยนรหัสผ่านหรือสร้างผู้ใช้ใหม่ แล้วลบ admin หากไม่ต้องการใช้งานต่อ\n")
        print("\n🛡️  รหัสผ่านของผู้ใช้ admin ถูกรีเซ็ตใหม่และบันทึกในไฟล์ admin_password.txt\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
