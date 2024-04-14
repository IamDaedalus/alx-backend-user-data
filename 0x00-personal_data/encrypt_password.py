#!/usr/bin/env python3
""" bcrypt password encryption """

import bcrypt


def hash_password(password: str) -> bytes:
    """ hash a password with bcrypt """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ check hashed password matches with the plain text password """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
