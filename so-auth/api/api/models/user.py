from datetime import datetime, timedelta

import jwt
import bcrypt
from flask import current_app as app

from models import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100, collation='NOCASE'), nullable=False, unique=True)
    pw_hash = db.Column(db.String(255), nullable=False)
    pw_salt = db.Column(db.String(255), nullable=False)

    failed_login_attempts = db.Column(db.Integer, nullable=False)
    last_login = db.Column(db.DateTime)
    last_logout = db.Column(db.DateTime)

    logged_in = db.Column(db.Boolean)
    remember_me = db.Column(db.Boolean)
    current_refresh_token = db.Column(db.String(255))
    last_contact = db.Column(db.DateTime)

    def __init__(self, username: str, password: str, remember_me: bool = False):
        now = datetime.now()
        self.username = username
        self.pw_salt = bcrypt.gensalt(12)
        self.pw_hash = bcrypt.hashpw(password.encode('UTF-8'), self.pw_salt)
        self.failed_login_attempts = 0
        self.logged_in = False
        self.remember_me = remember_me
        self.last_login = now
        self.last_contact = now

    def check_password(self, password):
        return bcrypt.hashpw(password=password.encode('UTF-8'), salt=self.pw_salt) == self.pw_hash

    def change_password(self, new_password):
        self.pw_hash = bcrypt.hashpw(new_password.encode('UTF-8'), self.pw_salt)

    @staticmethod
    def encode_token(user_id: int, username: str, is_refresh: bool = False):
        """
        Generates the auth token
        :param username: string
        :param user_id: integer
        :param is_refresh: boolean
        :return: string
        """
        try:
            utc_now = datetime.utcnow()
            if is_refresh:
                expire_time = timedelta(days=app.config.get('REFRESH_TOKEN_TIMEOUT'))
                context = 'refresh'
            else:
                expire_time = timedelta(days=0, minutes=app.config.get('AUTH_TOKEN_TIMEOUT'))
                context = 'auth'
            payload = {
                'exp': utc_now + expire_time,
                'iat': utc_now,
                'user_id': user_id,
                'username': username,
                'context': context
            }
            secret_key: str = app.config.get('SECRET_KEY')
            return jwt.encode(
                payload=payload,
                key=secret_key,
                algorithm='HS256'
            )
        except Exception as e:  # pragma: no cover
            return e

    @staticmethod
    def decode_token(auth_token: str, is_refresh: bool = False):
        """
        Decodes the auth token
        :param is_refresh: boolean
        :param auth_token: string
        :return: integer|string
        """
        invalid_token_message = 'Invalid token, please log in again'

        try:
            payload = jwt.decode(auth_token, key=app.config.get('SECRET_KEY'), algorithms=['HS256'])

            if is_refresh:
                if payload['context'] != 'refresh':
                    return {
                        'message': invalid_token_message,
                        'error_code': 401,
                    }
            else:
                if payload['context'] != 'auth':
                    return {
                        'message': invalid_token_message,
                        'error_code': 401,
                    }

            if not payload.keys().__contains__('username') or not payload.keys().__contains__('user_id') \
                    or not payload.keys().__contains__('context'):
                return {
                    'message': invalid_token_message,
                    'error_code': 401
                }
            else:
                return {
                    'id': payload['user_id'],
                    'username': payload['username'],
                    'context': payload['context']
                }
        except jwt.ExpiredSignatureError:
            if not is_refresh:
                return {
                    'message': 'Signature expired, please refresh token',
                    'error_code': 307,
                }
            else:
                return {
                    'message': 'Signature expired, please log in again',
                    'error_code': 401,
                }
        except jwt.InvalidTokenError:
            return {
                'message': invalid_token_message,
                'error_code': 401,
            }

