#!/usr/bin/env python3
""" basic auth module """


import base64 as b64
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ class for basic authentication """
    def extract_base64_authorization_header(self, auth_header: str) -> str:
        if auth_header is None or not isinstance(auth_header, str):
            return None
        if auth_header[:6] != "Basic ":
            return None

        return auth_header[6:]

    def decode_base64_authorization_header(
            self, b64_auth_header: str) -> str:
        if b64_auth_header is None or not isinstance(
                b64_auth_header, str):
            return None
        try:
            b64.decode(b64_auth_header)
        except Exception:
            return None

