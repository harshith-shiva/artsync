from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime
#from models import Message  # ← ADD THIS
#from models import Artist, Sponsor, Contractor, Event, Hosts, Funds, Message, Request  # ← ADD Request

from decimal import Decimal as PyDecimal  # <-- ADD THIS IMPORT
# ... other imports ...


import bcrypt
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


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


class Sponsor(db.Model):
    __tablename__ = 'Sponsors'
    sid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    logo = db.Column(db.String(255))
    contact_email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    sector = db.Column(db.String(100))
    reputation_score = db.Column(db.Integer, default=0)
    sponsored_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- SPONSOR REQUEST MODEL ---
class SponsorRequest(db.Model):
    __tablename__ = 'SponsorRequests'
    rid = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('Sponsors.sid', ondelete='CASCADE'))
    artist_id = db.Column(db.Integer, db.ForeignKey('Artist.aid', ondelete='CASCADE'))
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('pending', 'accepted', 'rejected'), default='pending')
    initiated_by = db.Column(db.Enum('artist', 'sponsor'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # --- Add relationship for easy querying ---
    Sponsor.requests_received = db.relationship('SponsorRequest', 
        foreign_keys='SponsorRequest.sponsor_id', 
        backref='sponsor', lazy=True)

    Artist.requests_received = db.relationship('SponsorRequest', 
        foreign_keys='SponsorRequest.artist_id', 
        backref='artist', lazy=True)

# --- Contractor Model ---
class Contractor(db.Model):
    __tablename__ = 'Contractor'
    cid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Event Model ---
class Event(db.Model):
    __tablename__ = 'Events'
    eid = db.Column(db.Integer, primary_key=True)
    ename = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50))
    event_date = db.Column(db.Date)
    event_time = db.Column(db.Time)
    venue = db.Column(db.String(100))
    capacity = db.Column(db.Integer)
    cid = db.Column(db.Integer, db.ForeignKey('Contractor.cid'))
    # --- ADD INSIDE Event class ---
    contractor = db.relationship('Contractor', backref='events')

# --- Contractor hosts Artist in Event ---
class Hosts(db.Model):
    __tablename__ = 'Hosts'
    hid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cid = db.Column(db.Integer, db.ForeignKey('Contractor.cid'), nullable=False)
    aid = db.Column(db.Integer, db.ForeignKey('Artist.aid'), nullable=False)
    eid = db.Column(db.Integer, db.ForeignKey('Events.eid'), nullable=False)
    status = db.Column(db.Enum('pending', 'confirmed', 'rejected'), default='pending')

    __table_args__ = (
        db.UniqueConstraint('cid', 'aid', 'eid', name='unique_application'),
    )

    contractor = db.relationship('Contractor', backref='host_applications')
    artist = db.relationship('Artist', backref='host_applications')
    event = db.relationship('Event', backref='host_applications')
# --- Sponsor funds Contractor's Event ---
class Funds(db.Model):
    __tablename__ = 'Funds'
    sid = db.Column(db.Integer, db.ForeignKey('Sponsors.sid'), primary_key=True)
    cid = db.Column(db.Integer, db.ForeignKey('Contractor.cid'), primary_key=True)
    eid = db.Column(db.Integer, db.ForeignKey('Events.eid'), primary_key=True)
    amount = db.Column(db.Numeric(10, 2))
    status = db.Column(db.Enum('pending', 'funded'), default='pending')

class Message(db.Model):
    __tablename__ = 'Messages'
    mid = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    sender_type = db.Column(db.Enum('artist', 'sponsor', 'contractor'))
    receiver_id = db.Column(db.Integer)
    receiver_type = db.Column(db.Enum('artist', 'sponsor', 'contractor'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Request(db.Model):
    __tablename__ = 'Request'
    rid = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.Integer, db.ForeignKey('Sponsors.sid'), nullable=False)
    aid = db.Column(db.Integer, db.ForeignKey('Artist.aid'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('pending', 'accepted', 'rejected'), default='pending')
    initiated_by = db.Column(db.Enum('sponsor', 'artist'), default='sponsor')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    sponsor = db.relationship('Sponsor', backref='requests')
    artist = db.relationship('Artist', backref='requests')


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
            session['artist_id'] = artist.aid
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

# --- SPONSOR: REGISTER ---
@app.route('/sponsor/register', methods=['GET', 'POST'])
def sponsor_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        sector = request.form.get('sector', '')

        if Sponsor.query.filter_by(contact_email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('sponsor_register'))

        sponsor = Sponsor(name=name, contact_email=email, sector=sector)
        sponsor.set_password(password)

        # Handle logo upload
        logo = request.files.get('logo')
        if logo and allowed_file(logo.filename):
            filename = secure_filename(logo.filename)
            logo_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'sponsors')
            os.makedirs(logo_dir, exist_ok=True)
            logo.save(os.path.join(logo_dir, filename))
            sponsor.logo = f"sponsors/{filename}"

        db.session.add(sponsor)
        db.session.commit()
        flash('Sponsor registered! Please login.', 'success')
        return redirect(url_for('sponsor_login'))
    return render_template('sponsor_register.html')

# --- SPONSOR: LOGIN ---
@app.route('/sponsor/login', methods=['GET', 'POST'])
def sponsor_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        sponsor = Sponsor.query.filter_by(contact_email=email).first()
        if sponsor and sponsor.check_password(password):
            session['sponsor_id'] = sponsor.sid
            flash('Logged in as sponsor!', 'success')
            return redirect(url_for('sponsor_dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('sponsor_login.html')

# --- SPONSOR: LOGOUT ---
@app.route('/sponsor/logout')
def sponsor_logout():
    session.pop('sponsor_id', None)
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

# --- SPONSOR: DASHBOARD ---
@app.route('/sponsor/dashboard')
def sponsor_dashboard():
    if 'sponsor_id' not in session:
        return redirect(url_for('sponsor_login'))
    sponsor = Sponsor.query.get(session['sponsor_id'])
    artists = Artist.query.all()
    events = Event.query.options(db.joinedload(Event.contractor)).all()
    
    return render_template('sponsor_dashboard.html', 
                           sponsor=sponsor, 
                           artists=artists, 
                           events=events)
    

# --- SPONSOR: SEND OFFER TO ARTIST ---

# --- ARTIST: VIEW TOP SPONSORS ---
@app.route('/artist/sponsors')
def artist_sponsors():
    if 'artist_id' not in session:
        return redirect(url_for('login'))
    sponsors = Sponsor.query.order_by(Sponsor.reputation_score.desc()).limit(10).all()
    return render_template('artist_sponsors.html', sponsors=sponsors)

# --- ARTIST: REQUEST SPONSORSHIP ---
@app.route('/artist/request_sponsor/<int:sid>', methods=['GET', 'POST'])
def request_sponsor(sid):
    if session.get('user_id') is None:
        return redirect(url_for('login'))
    sponsor = Sponsor.query.get_or_404(sid)
    if request.method == 'POST':
        message = request.form['message']
        req = SponsorRequest(
            sponsor_id=sid,
            artist_id=session['artist_id'],
            message=message,
            initiated_by='artist'
        )
        db.session.add(req)
        db.session.commit()
        flash('Request sent!', 'success')
        return redirect(url_for('artist_sponsors'))
    return render_template('request_sponsor.html', sponsor=sponsor)


@app.route('/sponsor/offer/<int:aid>', methods=['GET', 'POST'])
def sponsor_offer(aid):
    if 'sponsor_id' not in session:
        flash('Please login as sponsor.', 'error')
        return redirect(url_for('sponsor_login'))

    artist = Artist.query.get_or_404(aid)

    if request.method == 'POST':
        message = request.form['message']
        amount = request.form.get('amount', '')
        duration = request.form.get('duration', '')

        # Build full message
        full_message = message
        if amount:
            full_message += f"\n\nOffer Amount: ${amount}"
        if duration:
            full_message += f"\nDuration: {duration} month(s)"

        req = SponsorRequest(
            sponsor_id=session['sponsor_id'],
            artist_id=aid,
            message=full_message,
            initiated_by='sponsor'
        )
        db.session.add(req)
        db.session.commit()
        flash('Offer sent successfully!', 'success')
        return redirect(url_for('sponsor_dashboard'))

    return render_template('sponsor_offer.html', artist=artist)


# --- SPONSOR: VIEW INCOMING REQUESTS ---
@app.route('/sponsor/inbox')
def sponsor_inbox():
    if 'sponsor_id' not in session:
        return redirect(url_for('sponsor_login'))
    sid = session['sponsor_id']

    # Only show requests initiated by ARTIST
    requests = SponsorRequest.query.filter_by(
        sponsor_id=sid, initiated_by='artist'
    ).all()

    return render_template('sponsor_inbox.html', requests=requests)
# --- SPONSOR: ACCEPT/REJECT REQUEST ---
@app.route('/sponsor/request/<int:rid>/<action>')
def sponsor_handle_request(rid, action):
    if 'sponsor_id' not in session:
        return redirect(url_for('sponsor_login'))
    req = SponsorRequest.query.get_or_404(rid)
    if req.sponsor_id != session['sponsor_id']:
        flash('Unauthorized.', 'error')
        return redirect(url_for('sponsor_inbox'))
    if action == 'accept':
        req.status = 'accepted'
        req.sponsor.sponsored_count += 1
        req.sponsor.reputation_score += 20
        flash('Request accepted!', 'success')
    elif action == 'reject':
        req.status = 'rejected'
        flash('Request rejected.', 'info')
    db.session.commit()
    return redirect(url_for('sponsor_inbox'))

# --- ARTIST: VIEW INCOMING OFFERS ---
@app.route('/artist/inbox')
def artist_inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    aid = session['user_id']

    # 1. Sponsor Offers – only those initiated by sponsor
    sponsor_requests = db.session.query(SponsorRequest, Sponsor)\
        .join(Sponsor, SponsorRequest.sponsor_id == Sponsor.sid)\
        .filter(SponsorRequest.artist_id == aid, SponsorRequest.initiated_by == 'sponsor')\
        .all()

    # 2. Contractor Messages – accept/reject notifications
    contractor_messages = Message.query.filter_by(
        receiver_id=aid, receiver_type='artist'
    ).order_by(Message.timestamp.desc()).all()

    return render_template(
        'artist_inbox.html',
        sponsor_requests=sponsor_requests,
        contractor_messages=contractor_messages
    )
# --- ARTIST: ACCEPT/REJECT OFFER ---
@app.route('/artist/request/<int:rid>/<action>')
def artist_handle_request(rid, action):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    req = SponsorRequest.query.get_or_404(rid)
    if req.artist_id != session['user_id']:
        flash('Unauthorized.', 'error')
        return redirect(url_for('artist_inbox'))
    if action == 'accept':
        req.status = 'accepted'
        flash('Offer accepted!', 'success')
    elif action == 'reject':
        req.status = 'rejected'
        flash('Offer rejected.', 'info')
    db.session.commit()
    return redirect(url_for('artist_inbox'))
# --- Contractor: Login ---
@app.route('/contractor/login', methods=['GET', 'POST'])
def contractor_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        contractor = Contractor.query.filter_by(email=email).first()
        if contractor and contractor.check_password(password):
            session['contractor_id'] = contractor.cid
            flash('Contractor logged in!', 'success')
            return redirect(url_for('contractor_dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('contractor_login.html')


@app.route('/contractor/register', methods=['GET', 'POST'])
def contractor_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        location = request.form.get('location')

        if Contractor.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('contractor_register'))

        contractor = Contractor(name=name, email=email, location=location)
        contractor.set_password(password)
        db.session.add(contractor)
        db.session.commit()
        flash('Contractor registered!', 'success')
        return redirect(url_for('contractor_login'))
    return render_template('contractor_register.html')


# --- Contractor: Dashboard ---
@app.route('/contractor/dashboard')
def contractor_dashboard():
    if 'contractor_id' not in session:
        return redirect(url_for('contractor_login'))
    contractor = Contractor.query.get(session['contractor_id'])
    events = Event.query.filter_by(cid=contractor.cid).all()
    return render_template('contractor_dashboard.html', contractor=contractor, events=events)



# --- Contractor: Logout ---
@app.route('/contractor/logout')
def contractor_logout():
    session.pop('contractor_id', None)
    return redirect(url_for('login'))

# --- Create Event ---
@app.route('/contractor/event/create', methods=['GET', 'POST'])
def create_event():
    if 'contractor_id' not in session:
        return redirect(url_for('contractor_login'))
    if request.method == 'POST':
        event = Event(
            ename=request.form['ename'],
            event_type=request.form['event_type'],
            event_date=request.form['event_date'],
            event_time=request.form['event_time'],
            venue=request.form['venue'],
            capacity=request.form['capacity'],
            cid=session['contractor_id']
        )
        db.session.add(event)
        db.session.commit()
        flash('Event created!', 'success')
        return redirect(url_for('contractor_dashboard'))
    return render_template('create_event.html')

# --- Public Events Page ---
@app.route('/events')
def events_page():
    events = Event.query.options(db.joinedload(Event.contractor)).all()
    applications = Hosts.query.all() if 'user_id' in session else []
    fundings = Funds.query.all() if 'sponsor_id' in session else []  # ← ADD THIS
    
    return render_template('events.html', 
                           events=events, 
                           hosts=applications, 
                           funds=fundings)  # ← PASS TO TEMPLATE
# --- Artist Apply to Event ---

@app.route('/event/<int:eid>/apply', methods=['GET', 'POST'])
def apply_to_event(eid):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    event = Event.query.get_or_404(eid)
    aid = session['user_id']

    # CHECK IF ALREADY APPLIED
    existing = Hosts.query.filter_by(cid=event.cid, aid=aid, eid=eid).first()
    if existing:
        flash('You have already applied to this event.', 'info')
        return redirect(url_for('events_page'))

    if request.method == 'POST':
        host = Hosts(cid=event.cid, aid=aid, eid=eid, status='pending')
        db.session.add(host)
        db.session.commit()
        flash('Application sent successfully!', 'success')
        return redirect(url_for('events_page'))
    
    return render_template('apply_event.html', event=event)
# --- Sponsor Fund Event ---
@app.route('/event/<int:eid>/fund', methods=['GET', 'POST'])
def fund_event(eid):
    if 'sponsor_id' not in session:
        return redirect(url_for('sponsor_login'))
    event = Event.query.get_or_404(eid)
    sid = session['sponsor_id']

    # CHECK IF SPONSOR ALREADY FUNDED THIS EVENT
    existing = Funds.query.filter_by(sid=sid, cid=event.cid, eid=eid).first()
    if existing:
        flash('You have already funded this event.', 'info')
        return redirect(url_for('events_page'))

    if request.method == 'POST':
        amount = request.form['amount']
        fund = Funds(sid=sid, cid=event.cid, eid=eid, amount=amount, status='funded')
        db.session.add(fund)
        db.session.commit()
        flash('Funding applied successfully!', 'success')
        return redirect(url_for('events_page'))
    
    return render_template('fund_event.html', event=event)



@app.route('/sponsor/sent')
def sponsor_sent():
    if 'sponsor_id' not in session:
        return redirect(url_for('sponsor_login'))
    sid = session['sponsor_id']

    sent_offers = db.session.query(SponsorRequest, Artist)\
        .join(Artist, SponsorRequest.artist_id == Artist.aid)\
        .filter(SponsorRequest.sponsor_id == sid, SponsorRequest.initiated_by == 'sponsor')\
        .all()

    return render_template('sponsor_sent.html', sent_offers=sent_offers)









@app.route('/artist/stats')
def artist_stats():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    aid = session['user_id']

    # FIX: Use raw connection + consume ALL results
    connection = db.engine.raw_connection()
    try:
        cursor = connection.cursor()
        cursor.callproc('GetArtistStats', [aid])
        
        # Consume ALL result sets
        results = cursor.fetchall()
        if results:
            row = results[0]  # Only one row
            stats = {
                "name": row[0],
                "events": row[1],
                "funded_events": row[2],
                "funding": float(row[3])
            }
        else:
            stats = {"name": "", "events": 0, "funded_events": 0, "funding": 0}
        
        # Drain any extra result sets
        while cursor.nextset():
            pass
            
    finally:
        cursor.close()
        connection.close()

    return render_template('artist_stats.html', stats=stats)


@app.route('/contractor/inbox')
def contractor_inbox():
    if 'contractor_id' not in session:
        return redirect(url_for('contractor_login'))
    cid = session['contractor_id']
    
    # Get all applications for events hosted by this contractor
    applications = db.session.query(Hosts, Artist, Event)\
        .join(Artist, Hosts.aid == Artist.aid)\
        .join(Event, Hosts.eid == Event.eid)\
        .filter(Event.cid == cid, Hosts.status == 'pending')\
        .all()
    
    return render_template('contractor_inbox.html', applications=applications)

@app.route('/contractor/application/<int:hid>/<action>')
def handle_application(hid, action):
    if 'contractor_id' not in session:
        return redirect(url_for('contractor_login'))
    
    app = Hosts.query.get_or_404(hid)
    event = Event.query.get(app.eid)
    
    if event.cid != session['contractor_id']:
        flash('Unauthorized.', 'error')
        return redirect(url_for('contractor_inbox'))
    
    if action == 'accept':
        app.status = 'confirmed'
        message = f"Congratulations! Your application for '{event.ename}' has been ACCEPTED. Details will be shared soon."
    elif action == 'reject':
        app.status = 'rejected'
        message = f"Sadly, your application for '{event.ename}' has been rejected. Better luck next time!"
    else:
        flash('Invalid action.', 'error')
        return redirect(url_for('contractor_inbox'))
    
    db.session.add(Message(
        sender_id=session['contractor_id'],
        sender_type='contractor',
        receiver_id=app.aid,
        receiver_type='artist',
        content=message
    ))
    db.session.commit()
    
    flash(f'Application {action}ed and artist notified!', 'success')
    return redirect(url_for('contractor_inbox'))





@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures tables exist
    app.run(debug=True)