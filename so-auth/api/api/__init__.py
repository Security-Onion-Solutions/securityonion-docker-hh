import os

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from models import db
from routes import users, auth


def create_app():
    app = Flask(__name__)

    if app.env == 'development':
        app.config.from_object('config.DevelopConfig')
    else:
        app.config.from_object('config.BaseConfig')

    # init ORM
    with app.app_context():
        db.init_app(app)
        db.create_all()

    Limiter(app, default_limits=app.config.get('REQUEST_LIMITS'), key_func=get_remote_address)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=app.config.get('NUM_PROXIES'))

    app.register_blueprint(auth.blueprint)
    app.register_blueprint(users.blueprint)

    CORS(app)

    return app


if __name__ == '__main__':
    so_auth = create_app()
    so_auth.run()
