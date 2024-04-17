#!/usr/bin/env python3basic
""" basic auth module """

import base64 as b64
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """ class for basic authentication """
    def extract_base64_authorization_header(self, auth_header: str) -> str:
        """ extract the base64 encoded string from the header """
        if auth_header is None or \
            not isinstance(auth_header, str) or \
                auth_header[:6] != "Basic ":
            return None

        return auth_header[6:]

    def decode_base64_authorization_header(self, b64_auth_header: str) -> str:
        """ decode the base64 string; if it's not possible return None """
        if b64_auth_header is None or not isinstance(b64_auth_header, str):
            return None
        try:
            return b64.b64decode(b64_auth_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_b64_auth_header: str) -> \
            (str, str):
        """ extracts the user's credentials from a decoded base64 header """
        if decoded_b64_auth_header is None or \
            not isinstance(decoded_b64_auth_header, str) or \
                ':' not in decoded_b64_auth_header:
            return (None, None)
        c = decoded_b64_auth_header.index(':')
        return (decoded_b64_auth_header[:c], decoded_b64_auth_header[c + 1:])

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> \
            TypeVar('User'):
        """ checks user's credentials against the database """
        if user_email is None or not isinstance(user_email, str) or \
                user_pwd is None or not isinstance(user_pwd, str):
            return None

        matching_users = User.search({"email": user_email})
        if matching_users is None:
            return None
        for user in matching_users:
            if not user.is_valid_password(user_pwd):
                return None
            return user

    def current_user(self, request=None) -> TypeVar('User'):
        """ retrieves the user instance for a request """
        auth_header = self.authorization_header(request)
        b64_auth_header = self.extract_base64_authorization_header(auth_header)
        decoded_b64_auth_header = self.decode_base64_authorization_header(
            b64_auth_header)
        user_email, user_pwd = self.extract_user_credentials(
            decoded_b64_auth_header)
        return self.user_object_from_credentials(user_email, user_pwd)
