# imports and dependencies
from flask import Flask
from flask import jsonify
from flask import request
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import pandas as pd
import re

# initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "overlysecret"  # Change this!
jwt = JWTManager(app)
# Initializing database
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# search endpoint
book_title_df = pd.read_json("./books.json")
vectorizer = TfidfVectorizer()
tfidf = vectorizer.fit_transform(book_title_df["mod_title"])


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self) -> str:
        return f"{self.username}"


class User_Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


app.app_context().push()


@app.route("/")
def home():
    return "you are in flask homepage"


@app.route('/register', methods=['GET', 'POST'])
def register():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if username is None or password is None:
        return {"error": "missing parameters. Failed to register"}, 400

    user = User(username=username,
                password=bcrypt.generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return {"message": "User created successfully."}, 201


@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if username is None or password is None:
        return {"error": "Missing required parameters"}, 400

    user = User.query.filter_by(username=username).first()

    if user is None or not user.verify_password(password):
        return {"error": "Invalid credentials"}, 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route("/top50books", methods=["GET"])
def top50books():
    data = pd.read_json("./top_50_books.json")
    return data.to_json(orient='records')


@app.route("/search", methods=["POST", "GET"])
def search():
    query = request.json.get("book_title", None)
    if query is None:
        return {"error": "Missing required parameters"}, 400
    processed_query = re.sub("[^a-zA-Z0-9 ]", "", query.lower())
    query_vec = vectorizer.transform([processed_query])
    similarity = cosine_similarity(query_vec, tfidf).flatten()
    indices = np.argpartition(similarity, -10)[-10:]
    results = book_title_df.iloc[indices]
    return results.head(4).to_json(orient="records")


@app.route("/addbook", methods=["POST", "GET"])
def add_book_user():
    book_id = request.json.get("book_id", None)
    username = request.json.get("username", None)
    if book_id is None or username is None:
        return {"error": "Missing required parameters"}, 400
    user = User.query.filter_by(username=username).first()
    user_id = user.id
    user_book = User_Book(book_id=book_id, user_id=user_id)
    db.session.add(user_book)
    db.session.commit()
    return {"message": "Book added successfully."}, 201


@app.route("/getrecommendations", methods=["POST", "GET"])
def get_recommendations():
    username = request.json.get("username", None)
    if username is None:
        return {"error": "Mising required parameters"}, 400
    user = User.query.filter_by(username=username).first()
    user_id = user.id
    object_list = db.session.query(User_Book.book_id).filter(
        User_Book.user_id == user_id).all()
    book_list = []
    for item in object_list:
        book_list.append(item[0])
    return jsonify(book_list), 201


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
