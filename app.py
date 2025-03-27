import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from transformers import pipeline
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# PostgreSQL connection via environment variables
db_user = os.environ.get('DB_USER')
db_password = os.environ.get('DB_PASSWORD')
db_host = os.environ.get('DB_HOST')
db_port = os.environ.get('DB_PORT', '5432')  # default PostgreSQL port
db_name = os.environ.get('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f'postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    analyses = db.relationship('Analysis', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# Analysis model
class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create tables
@app.before_first_request
def create_tables():
    db.create_all()

# Hugging Face sentiment analyzer
sentiment_analyzer = pipeline("sentiment-analysis")

# Routes

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    
    if not name or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 400
    
    new_user = User(name=name, email=email)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No input data provided"}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({"token": access_token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/analyze', methods=['POST'])
@jwt_required()
def analyze():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400
    
    text = data['text']
    result = sentiment_analyzer(text)[0]
    label = result['label']
    score = result['score']
    
    analysis = Analysis(text=text, sentiment=label, confidence=score, user_id=user_id)
    db.session.add(analysis)
    db.session.commit()
    
    return jsonify({
        "text": text,
        "sentiment": label,
        "confidence": score
    })

@app.route('/history', methods=['GET'])
@jwt_required()
def history():
    user_id = get_jwt_identity()
    analyses = Analysis.query.filter_by(user_id=user_id).order_by(Analysis.timestamp.desc()).all()
    
    results = []
    for a in analyses:
        results.append({
            "id": a.id,
            "text": a.text,
            "sentiment": a.sentiment,
            "confidence": a.confidence,
            "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
