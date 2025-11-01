from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from decimal import Decimal as PyDecimal  # <-- ADD THIS IMPORT
# ... other imports ...


import bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:password@localhost/artsync'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Models ---
class Artist(db.Model):
    __tablename__ = 'Artist'
    aid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    age = db.Column(db.Integer)
    type = db.Column(db.String(50))
    location = db.Column(db.String(100))
    socials = db.Column(db.String(255))
    description = db.Column(db.Text)
    profile_pic = db.Column(db.String(255))  # NEW

    portfolio = db.relationship('Portfolio', backref='artist', uselist=False)
    buyers = db.relationship('BuysFrom', backref='artist', lazy=True)

class Portfolio(db.Model):
    __tablename__ = 'Portfolio'
    portfolio_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    aid = db.Column(db.Integer, db.ForeignKey('Artist.aid'), nullable=False)
    license_info = db.Column(db.String(255))
    description = db.Column(db.Text)
    visibility = db.Column(db.Enum('public', 'private'), default='public')

    samples = db.relationship('ArtSample', backref='portfolio', cascade='all, delete-orphan')

class ArtSample(db.Model):
    __tablename__ = 'ArtSample'
    sample_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    portfolio_id = db.Column(db.Integer, db.ForeignKey('Portfolio.portfolio_id'), nullable=False)
    image_path = db.Column(db.String(255))
    art_description = db.Column(db.Text)
    status = db.Column(db.Enum('sold', 'unsold'), default='unsold')


# --- ADD AFTER Artist model ---
class Buyer(db.Model):
    __tablename__ = 'Buyer'
    bid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100))
    location = db.Column(db.String(100))

    requests = db.relationship('BuysFrom', backref='buyer', cascade='all, delete-orphan')
    

# --- ADD BuysFrom model ---
class BuysFrom(db.Model):
    __tablename__ = 'BuysFrom'
    bid = db.Column(db.Integer, db.ForeignKey('Buyer.bid'), primary_key=True)
    aid = db.Column(db.Integer, db.ForeignKey('Artist.aid'), primary_key=True)
    quoted_amount = db.Column(db.Numeric(10, 2))
    need_description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # NEW: pending, accepted, rejected


# --- Helper: Check file extension ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        artist = Artist.query.filter_by(email=email).first()
        if artist and bcrypt.checkpw(password, artist.password.encode('utf-8')):
            session['user_id'] = artist.aid
            session['user_name'] = artist.name
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        age = request.form.get('age')
        type_ = request.form['type']
        location = request.form.get('location')
        socials = request.form.get('socials')

        if Artist.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))

        try:
            age = int(age) if age and age.strip() else None
        except ValueError:
            flash('Invalid age format.', 'error')
            return redirect(url_for('signup'))

        hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
        new_artist = Artist(
            name=name, email=email, password=hashed, age=age,
            type=type_, location=location, socials=socials
        )
        try:
            db.session.add(new_artist)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('signup.html')

# --- UPDATE dashboard route ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'error')
        return redirect(url_for('login'))
    artist = Artist.query.get(session['user_id'])
    requests = BuysFrom.query.filter_by(aid=artist.aid).all()
    return render_template('dashboard.html',
                           user_name=session['user_name'],
                           artist=artist,
                           requests=requests)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    artist = Artist.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Update text fields
        artist.name = request.form['name']
        artist.age = request.form.get('age') or None
        if artist.age is not None:
            try:
                artist.age = int(artist.age)
            except:
                flash('Invalid age.', 'error')
                return redirect(url_for('profile'))
        
        artist.type = request.form['type']
        artist.location = request.form.get('location') or None
        artist.socials = request.form.get('socials') or None
        artist.description = request.form.get('description') or None

        # Handle profile picture
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                artist.profile_pic = filename
            elif file and file.filename != '':
                flash('Invalid file type for profile picture.', 'error')

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('profile.html', artist=artist)

# --- Portfolio Routes ---
@app.route('/portfolio')
def portfolio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    artist = Artist.query.get(session['user_id'])
    portfolio = artist.portfolio
    return render_template('portfolio.html', portfolio=portfolio)

@app.route('/portfolio/create', methods=['GET', 'POST'])
def create_portfolio():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    artist = Artist.query.get(session['user_id'])
    if artist.portfolio:
        flash('You already have a portfolio.', 'info')
        return redirect(url_for('portfolio'))

    if request.method == 'POST':
        license_info = request.form['license_info']
        description = request.form['description']
        visibility = request.form['visibility']

        new_portfolio = Portfolio(
            aid=artist.aid,
            license_info=license_info,
            description=description,
            visibility=visibility
        )
        try:
            db.session.add(new_portfolio)
            db.session.commit()
            flash('Portfolio created!', 'success')
            return redirect(url_for('portfolio'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('create_portfolio.html')

@app.route('/portfolio/add_sample', methods=['GET', 'POST'])
def add_sample():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    artist = Artist.query.get(session['user_id'])
    if not artist.portfolio:
        flash('Create a portfolio first.', 'error')
        return redirect(url_for('create_portfolio'))

    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No file selected.', 'error')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            art_desc = request.form['art_description']
            status = request.form['status']

            sample = ArtSample(
                portfolio_id=artist.portfolio.portfolio_id,
                image_path=filename,
                art_description=art_desc,
                status=status
            )
            try:
                db.session.add(sample)
                db.session.commit()
                flash('Art sample added!', 'success')
                return redirect(url_for('portfolio'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'error')
        else:
            flash('Invalid file type.', 'error')
    return render_template('add_sample.html', portfolio=artist.portfolio)

@app.route('/portfolio/edit_sample/<int:sample_id>', methods=['GET', 'POST'])
def edit_sample(sample_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sample = ArtSample.query.get_or_404(sample_id)
    if sample.portfolio.aid != session['user_id']:
        flash('Unauthorized.', 'error')
        return redirect(url_for('portfolio'))

    if request.method == 'POST':
        sample.art_description = request.form['art_description']
        sample.status = request.form['status']

        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                sample.image_path = filename

        try:
            db.session.commit()
            flash('Sample updated!', 'success')
            return redirect(url_for('portfolio'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('edit_sample.html', sample=sample)

@app.route('/portfolio/delete_sample/<int:sample_id>')
def delete_sample(sample_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sample = ArtSample.query.get_or_404(sample_id)
    if sample.portfolio.aid != session['user_id']:
        flash('Unauthorized.', 'error')
        return redirect(url_for('portfolio'))

    try:
        db.session.delete(sample)
        db.session.commit()
        flash('Sample deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('portfolio'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# --- Buyer Login / Signup ---
@app.route('/buyer/login', methods=['GET', 'POST'])
def buyer_login():
    if request.method == 'POST':
        email = request.form['email']
        buyer = Buyer.query.filter_by(email=email).first()
        if buyer:
            session['buyer_id'] = buyer.bid
            session['buyer_name'] = buyer.name
            flash('Buyer login successful!', 'success')
            return redirect(url_for('buyer_dashboard'))
        else:
            flash('Buyer not found. Please sign up.', 'error')
    return render_template('buyer_login.html')

@app.route('/buyer/signup', methods=['GET', 'POST'])
def buyer_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        location = request.form.get('location')

        if Buyer.query.filter_by(email=email).first():
            flash('Email already in use.', 'error')
            return redirect(url_for('buyer_signup'))

        new_buyer = Buyer(name=name, email=email, location=location)
        try:
            db.session.add(new_buyer)
            db.session.commit()
            flash('Buyer account created! Please log in.', 'success')
            return redirect(url_for('buyer_login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('buyer_signup.html')


@app.route('/buyer/dashboard')
def buyer_dashboard():
    if 'buyer_id' not in session:
        return redirect(url_for('buyer_login'))
    artists = Artist.query.all()
    return render_template('buyer_dashboard.html', artists=artists)


@app.route('/buyer/logout')
def buyer_logout():
    session.pop('buyer_id', None)
    session.pop('buyer_name', None)
    flash('Logged out.', 'success')
    return redirect(url_for('buyer_login'))

@app.route('/artist/<int:aid>')
def public_profile(aid):
    artist = Artist.query.get_or_404(aid)
    is_buyer = 'buyer_id' in session
    is_owner = 'user_id' in session and session['user_id'] == aid
    return render_template('public_profile.html', artist=artist, is_buyer=is_buyer, is_owner=is_owner)


@app.route('/request_quote/<int:aid>', methods=['GET', 'POST'])
def request_quote(aid):
    if 'buyer_id' not in session:
        flash('Please log in as buyer.', 'error')
        return redirect(url_for('buyer_login'))
    
    artist = Artist.query.get_or_404(aid)
    buyer = Buyer.query.get(session['buyer_id'])

    if request.method == 'POST':
        try:
            amount = PyDecimal(request.form['quoted_amount'])
        except:
            flash('Invalid amount.', 'error')
            return redirect(url_for('request_quote', aid=aid))

        desc = request.form['need_description']

        existing = BuysFrom.query.filter_by(bid=buyer.bid, aid=aid).first()
        if existing:
            flash('You already sent a request to this artist.', 'error')
        else:
            req = BuysFrom(bid=buyer.bid, aid=aid, quoted_amount=amount, need_description=desc)
            db.session.add(req)
            db.session.commit()
            flash('Quote request sent successfully!', 'success')
        return redirect(url_for('public_profile', aid=aid))

    return render_template('request_quote.html', artist=artist)


@app.route('/request/accept/<int:aid>/<int:bid>')
def accept_request(aid, bid):
    if 'user_id' not in session or session['user_id'] != aid:
        flash('Unauthorized.', 'error')
        return redirect(url_for('dashboard'))
    
    req = BuysFrom.query.filter_by(aid=aid, bid=bid).first_or_404()
    req.status = 'accepted'
    db.session.commit()
    flash('Request accepted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/request/reject/<int:aid>/<int:bid>')
def reject_request(aid, bid):
    if 'user_id' not in session or session['user_id'] != aid:
        flash('Unauthorized.', 'error')
        return redirect(url_for('dashboard'))
    
    req = BuysFrom.query.filter_by(aid=aid, bid=bid).first_or_404()
    req.status = 'rejected'
    db.session.commit()
    flash('Request rejected.', 'info')
    return redirect(url_for('dashboard'))






@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures tables exist
    app.run(debug=True)