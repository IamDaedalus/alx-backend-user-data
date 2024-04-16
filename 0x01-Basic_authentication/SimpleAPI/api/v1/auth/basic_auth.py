#!/usr/bin/env python3
""" basic auth module """


from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ class for basic authentication """
    def extract_base64_authorization_header(self, auth_header: str) -> str:
        if auth_header is None or isinstance(str, auth_header):
            return None
        if auth_header[0:6] != "Basic ":
            return None

