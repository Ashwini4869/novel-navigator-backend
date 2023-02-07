from flask import Flask
from flask import jsonify
from flask import request
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "overlysecret"  # Change this!
jwt = JWTManager(app)


@app.route("/")
def home():
    return "you are in flask homepage"


@app.route("/welcome")
def welcome():
    d = {
        "hello": "hello"
    }

    return jsonify(d)


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "test" or password != "test":
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)
