import os

import jwt
from datetime import datetime, timedelta

from flask_testing import TestCase
from flask import current_app

from api import create_app
from models import db
from tests import SQLALCHEMY_DATABASE_URI

from models.user import User


class TestUser(TestCase):
    secret_key: str

    def create_app(self):
        app = create_app()
        app.testing = True
        app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
        return app

    def setUp(self) -> None:
        user = User('test_username', 'test_password')

        db.create_all()
        db.session.add(user)
        db.session.commit()

        self.secret_key = current_app.config.get("SECRET_KEY")

    def tearDown(self) -> None:
        db.session.remove()
        db.drop_all()
        os.remove('db.testing.sqlite')

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove('secret')
        except FileNotFoundError:  # pragma: no cover
            pass

    def test_creation(self):
        user = User.query.filter_by(username='test_username').first()
        self.assertEqual(user.username, 'test_username')

    def test_password_check(self):
        user = User.query.filter_by(username='test_username').first()

        self.assertTrue(user.check_password('test_password'))

    def test_change_password(self):
        user = User('test_username', 'test_password')
        user.change_password('test_pass_new')
        self.assertTrue(user.check_password('test_pass_new'))

    def test_encode_auth_token(self):
        user = User.query.filter_by(username='test_username').first()

        User.encode_token(user.id, user.username)

    def test_decode_auth_token_success(self):
        user = User.query.filter_by(username='test_username').first()

        token = User.encode_token(user.id, user.username)
        User.decode_token(token)

    def test_decode_auth_token_fail_missing_key(self):
        now = datetime.utcnow()

        payload = {
            'exp': now + timedelta(10),
            'iat': now,
            'username': 'test_username',
            'context': 'auth'
        }

        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm='HS256'
        )

        decode_result = User.decode_token(token)

        self.assertEqual(401, decode_result.get('error_code'))
        self.assertEqual('Invalid token, please log in again', decode_result.get('message'))

    def test_decode_auth_token_expired(self):
        now = datetime.utcnow()
        user = User.query.filter_by(username='test_username').first()

        payload = {
            'exp': now - timedelta(10),
            'iat': now,
            'user_id': user.id,
            'username': 'test_username',
            'context': 'auth'
        }

        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm='HS256'
        )

        decode_result = User.decode_token(token)

        self.assertEqual(307, decode_result.get('error_code'))
        self.assertEqual('Signature expired, please refresh token', decode_result.get('message'))

    def test_decode_auth_token_inavlid_context(self):
        now = datetime.utcnow()
        user = User.query.filter_by(username='test_username').first()

        payload = {
            'exp': now + timedelta(10),
            'iat': now,
            'user_id': user.id,
            'username': 'test_username',
            'context': 'refresh'
        }

        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm='HS256'
        )

        decode_result = User.decode_token(token)

        self.assertEqual(401, decode_result.get('error_code'))
        self.assertEqual('Invalid token, please log in again', decode_result.get('message'))

    def test_decode_auth_token_invalid(self):
        token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1Njk0MzE1MzAsImlhdCI6MTU2OTQyNzkzMCwidXNlcl9pZCI6M' \
                'SwidXNlcm5hbWUiOiJ0ZXN0MSIsImNvbnRleHQiOiJhdXRoIn0.DZHGyFYpxKJPZ_6WnCsuLpkqiJhO5w-OnfY5LCwrH_k'

        decode_result = User.decode_token(token)

        self.assertEqual(401, decode_result.get('error_code'))
        self.assertEqual('Invalid token, please log in again', decode_result.get('message'))

    def test_encode_refresh_token(self):
        user = User.query.filter_by(username='test_username').first()

        User.encode_token(user.id, user.username, is_refresh=True)

    def test_decode_refresh_token_success(self):
        user = User.query.filter_by(username='test_username').first()

        token = User.encode_token(user.id, user.username, is_refresh=True)
        user.decode_token(token)

    def test_decode_refresh_token_expired(self):
        now = datetime.utcnow()
        user = User.query.filter_by(username='test_username').first()

        payload = {
            'exp': now - timedelta(10),
            'iat': now,
            'user_id': user.id,
            'username': 'test_username',
            'context': 'refresh'
        }

        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm='HS256'
        )

        decode_result = User.decode_token(token, is_refresh=True)

        self.assertEqual(401, decode_result.get('error_code'))
        self.assertEqual('Signature expired, please log in again', decode_result.get('message'))

    def test_decode_refresh_token_inavlid_context(self):
        now = datetime.utcnow()
        user = User.query.filter_by(username='test_username').first()

        payload = {
            'exp': now + timedelta(10),
            'iat': now,
            'user_id': user.id,
            'username': 'test_username',
            'context': 'auth'
        }

        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm='HS256'
        )

        decode_result = User.decode_token(token, is_refresh=True)

        self.assertEqual(401, decode_result.get('error_code'))
        self.assertEqual('Invalid token, please log in again', decode_result.get('message'))
