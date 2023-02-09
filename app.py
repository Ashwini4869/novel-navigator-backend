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

# initialization
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "overlysecret"  # Change this!
jwt = JWTManager(app)
# Initializing database
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self) -> str:
        return f"{self.username}"


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
