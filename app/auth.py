
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from . import db
from .models import User
from sqlalchemy import select
from datetime import datetime, timezone

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()


@basic_auth.verify_password
def verify_password(email, password):
    user = db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is not None and user.check_password(password):
        return user
    return None

@basic_auth.error_handler
def basic_auth_error_handler(status_code):
    return {'error': 'Incorrect username and/or password. Please try again'}, status_code

@token_auth.verify_token
def verify_token(token):
    user = db.session.execute(select(User).where(User.token == token)).scalar_one_or_none()
    if user is not None and user.token_expiration > datetime.now(timezone.utc):
        return user
    return None

@token_auth.error_handler
def token_auth_error_handler(status_code):
    return {'error': 'Incorrect token. Please try again'}, status_code
