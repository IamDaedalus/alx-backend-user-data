#!/usr/bin/env python3
""" module for session authentication view """

from flask import jsonify, request
from flask.app import os
from api.v1.views import app_views
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login_authentication():
    """ session authentication views """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or email == "":
        return {"error": "email missing"}, 400
    if not password or password == "":
        return {"error": "password missing"}, 400

    users = User.search({"email": email})
    if not users:
        return {"error": "no user found for this email"}, 404

    for user in users:
        if user.is_valid_password(password):
            from api.v1.app import auth
            session_id = auth.create_session(user.id)
            response = jsonify(user.to_json())
            session_cookie = os.getenv("SESSION_NAME")
            response.set_cookie(session_cookie, session_id)
            return response

        return {"error": "wrong password"}, 401
