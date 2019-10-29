import os
from datetime import datetime, timedelta

import jwt
from flask import current_app
from flask_testing import TestCase

from api import create_app
from models.user import User
from models import db
from tests import SQLALCHEMY_DATABASE_URI


class TestAuth(TestCase):
    valid_jwt_auth: str
    valid_jwt_refresh: str
    secret_key: str

    def create_app(self):
        app = create_app()
        app.testing = True
        app.config['LIVESERVER_PORT'] = 0
        app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
        return app

    def setUp(self) -> None:
        db.create_all()

        user = User('test_username', 'test_password')
        db.session.add(user)
        db.session.commit()
        assert user in db.session

        self.valid_jwt_auth = User.encode_token(user.id, user.username)
        self.valid_jwt_refresh = User.encode_token(user.id, user.username, is_refresh=True)
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

    def test_auth_check(self):
        self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password'
        ))

        response = self.client.post('/auth/')

        self.assert200(response)

    def test_register(self):
        response = self.client.post('/auth/register', json=dict(
            username='test_username_new',
            password='super_secret_password'
        ))

        self.assert200(response)

    def test_register_remote(self):
        response = self.client.post(
            '/auth/register',
            json=dict(username='test_username_new', password='super_secret_password'),
            environ_base={'REMOTE_ADDR': '192.168.1.1'}
        )

        self.assert401(response)

    def test_register_bad_password(self):
        response = self.client.post('/auth/register', json=dict(
            username='test_username_new',
            password='2shrt'
        ))

        self.assert400(response)

    def test_register_existing_user(self):
        response = self.client.post('/auth/register', json=dict(
            username='test_username',
            password='super_secret_password'
        ))

        self.assert401(response)

    def test_login(self):
        response = self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password'
        ))

        self.assert200(response)

    def test_login_remember_me(self):
        response = self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password',
            remember_me='true'
        ))

        self.assert200(response)

    def test_login_failure_wrong_user(self):
        response = self.client.post('/auth/login', json=dict(
            username='test_username_wrong',
            password='test_password'
        ))

        self.assert401(response)

    def test_login_failure_wrong_pass(self):
        response = self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password_wrong'
        ))

        self.assert401(response)

    def test_logout_before_login(self):
        self.client.set_cookie('localhost', 'Auth-Token', self.valid_jwt_auth)
        response = self.client.post('/auth/logout')

        self.assert401(response)

    def test_logout(self):
        self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password'
        ))

        response = self.client.post('/auth/logout')

        self.assert200(response)

    def test_request_bad_token(self):
        self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password'
        ))

        self.client.set_cookie('localhost', 'Auth-Token', self.valid_jwt_auth + b'a')
        response = self.client.post('/auth/')

        self.assert401(response)

    def test_request_nonexistent_user(self):
        now = datetime.utcnow()

        payload = {
            'exp': now + timedelta(10),
            'iat': now,
            'user_id': 42,
            'username': 'test_username',
            'context': 'auth'
        }

        token = jwt.encode(
            payload=payload,
            key=self.secret_key,
            algorithm='HS256'
        )

        self.client.set_cookie('localhost', 'Auth-Token', token)

        response = self.client.post('/auth/')

        self.assert403(response)

    def test_request_no_token(self):
        self.client.set_cookie('localhost', 'Auth-Token', '', expires=0)

        response = self.client.post('/auth/')

        self.assert500(response)

    def test_renew_token(self):
        self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password',
            remember_me='true'
        ))

        response = self.client.post('/auth/renew', headers={'X-Original-URI': 'test_uri'})

        self.assertRedirects(response, 'auth/test_uri')

    def test_renew_token_no_original_uri(self):
        self.client.post('/auth/login', json=dict(
            username='test_username',
            password='test_password',
            remember_me='true'
        ))

        response = self.client.post('/auth/renew')

        self.assert200(response)
