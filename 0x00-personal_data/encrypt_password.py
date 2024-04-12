#!/usr/bin/env python3

from bcrypt import checkpw, hashpw, gensalt


def hash_password(password: str) -> bytes:
    """ hash a password with bcrypt """
    salt = gensalt()
    return hashpw(password.encode('utf-8'), salt)

def is_valid(hashed_password: bytes, password: str) -> bool:
    """ check hashed password matches with the plain text password """
    return checkpw(password.encode('utf-8'), hashed_password)
