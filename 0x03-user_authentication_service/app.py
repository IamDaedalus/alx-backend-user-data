#!/usr/bin/env python3
""" Main file """

from flask import Flask, abort, jsonify, make_response, redirect, request
from sqlalchemy.orm.exc import NoResultFound
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route("/", methods=['GET'], strict_slashes=False)
def hello():
    """ intro to the flask app """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'], strict_slashes=False)
def users():
    """ register a user """
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 201
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=['POST'], strict_slashes=False)
def login():
    """ login a user """
    email = request.form.get("email")
    password = request.form.get("password")
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = make_response(
                jsonify({"email": email, "message": "logged in"}))
        response.set_cookie("session_id", session_id)
        return response
    abort(401)


@app.route("/sessions", methods=['DELETE'], strict_slashes=False)
def logout():
    """ logout a user """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(str(session_id))
    if session_id is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/profile", methods=['GET'], strict_slashes=False)
def profile():
    """ get the user profile """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(str(session_id))
    if session_id is None or user is None:
        abort(403)
    return jsonify({"email": user.email}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
