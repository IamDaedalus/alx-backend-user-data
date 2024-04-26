#!/usr/bin/env python3
""" authentication module """

from typing import NoReturn

from werkzeug.datastructures.mixins import V
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
import bcrypt


def _hash_password(password: str) -> bytes:
    """ hash and return a password """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """ auth class to interact with the authentication database """

    def __init__(self) -> None:
        """ initialize the auth class """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ register a new user """
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """ check if a user is valid """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                    password.encode('utf-8'), user.hashed_password)
        except NoResultFound:
            return False

    def _generate_uuid(self) -> str:
        """ generate uuid """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """ create a session for a user """
        try:
            user = self._db.find_user_by(email=email)
            session_id = self._generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """ get a user based on a session id """
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """ destroy a session """
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ get a reset password token """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = self._generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
        except NoReturn:
            raise ValueError
