import os

from flask import current_app
from flask_testing import TestCase

from api import create_app, Admin
from api.models.user import User
from api.models import DB
from api.tests import SQLALCHEMY_DATABASE_URI


class TestUsers(TestCase):
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
        DB.create_all()

        # check if admin entry already exists and if not, add it
        if not Admin.query.filter_by(created=True).first():
            admin_instance = Admin()
            DB.session.add(admin_instance)
            DB.session.commit()

        user = User('test_username', 'test_password')
        DB.session.add(user)
        DB.session.commit()
        assert user in DB.session

        self.valid_jwt_auth = User.encode_token(user.id, user.username)
        self.valid_jwt_refresh = User.encode_token(
            user.id, user.username, is_refresh=True)
        self.secret_key = current_app.config.get("SECRET_KEY")

    def tearDown(self) -> None:
        DB.session.remove()
        DB.drop_all()
        if os.path.exists('db.testing.sqlite'):
            os.remove('db.testing.sqlite')

    @classmethod
    def tearDownClass(cls):
        try:
            if os.path.exists('db.testing.sqlite'):
                os.remove('db.testing.sqlite')
            os.remove('secret')
        except FileNotFoundError:  # pragma: no cover
            pass

    def test_change_password(self):
        response = self.client.put('/users/change_password', json=dict(
            username='test_username',
            old_password='test_password',
            new_password='test_password_new'
        ))

        self.assert200(response)

    def test_change_password_wrong_old_password(self):
        response = self.client.put('/users/change_password', json=dict(
            username='test_username',
            old_password='test_password_wrong',
            new_password='test_password_new'
        ))

        self.assert401(response)

    def test_change_password_missing_old_password(self):
        response = self.client.put('/users/change_password', json=dict(
            username='test_username',
            new_password='test_password_new'
        ))

        self.assert400(response)

    def test_change_password_missing_new_password(self):
        response = self.client.put('/users/change_password', json=dict(
            username='test_username',
            old_password='test_password'
        ))

        self.assert400(response)

    def test_change_password_bad_new_password(self):
        response = self.client.put('/users/change_password', json=dict(
            username='test_username',
            old_password='test_password',
            new_password='2shrt'
        ))

        self.assert400(response)
