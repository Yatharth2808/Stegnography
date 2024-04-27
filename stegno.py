from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from steganography.steganography import Steganography
import os
from flask import session

# Initialize Flask app
app = Flask(__name__, template_folder='/Users/yatharthgautam/Spring 2024/IS_2/Ass4/templates')

# Configuration
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///website.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'wav', 'bin', 'dat', 'raw'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)

# Encoding function
def encode(file_path, message, starting_bit, length):
    message_hex = message.encode('utf-8').hex()
    message_bytes = bytes.fromhex(message_hex)
    
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())
    
    byte_index = starting_bit
    hex_index = 0
    while hex_index < len(message_bytes):
        if byte_index >= len(data):
            break
        
        data[byte_index] = message_bytes[hex_index]
        hex_index += 1
        byte_index += length
    
    with open(file_path, 'wb') as f:
        f.write(data)

# Decoding function
def decode(file_path, starting_bit, length):
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())
    
    extracted_bytes = bytearray()
    byte_index = starting_bit
    while byte_index < len(data):
        extracted_bytes.append(data[byte_index])
        byte_index += length
    
    try:
        decoded_message = extracted_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        decoded_message = f"Error decoding message: {e}"
    
    return decoded_message

# Login manager loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user:
            flash('Username does not exist', 'error')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Password is incorrect', 'error')
            return redirect(url_for('login'))

        login_user(user)

        return redirect(url_for('upload'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        message = request.form['message']
        starting_bit = int(request.form['starting_bit'])
        length = int(request.form['length'])

        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload'))

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        encode(os.path.join(app.config['UPLOAD_FOLDER'], filename), message, starting_bit, length)

        return redirect(url_for('view', filename=filename))

    return render_template('upload.html')

@app.route('/view/<filename>')
def view(filename):
    return render_template('decode.html', filename=filename)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)

from flask import session

@app.route('/decode', methods=['GET', 'POST'])
@login_required
def decode_page():
    if request.method == 'POST':
        file = request.files['file']

        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('decode_page'))

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        starting_bit = int(request.form.get('starting_bit', 0))
        length = int(request.form.get('length', 8))

        message = decode(os.path.join(app.config['UPLOAD_FOLDER'], filename), starting_bit, length)

        return render_template('decoded.html', message=message)  # Change this line to redirect to decoded.html

    return render_template('decode.html')



@app.route('/decoded')
@login_required
def decoded():
    # Retrieve the decoded message from the session
    message = session.pop('decoded_message', None)
    if message is None:
        flash('No decoded message found', 'error')
        return redirect(url_for('home'))

    return render_template('decoded.html', message=message)


# Running the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
