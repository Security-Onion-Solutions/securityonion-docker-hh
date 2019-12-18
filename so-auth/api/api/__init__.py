from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from models import db
from models.admin import Admin
from routes import users, auth, admin


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

        # check if admin entry already exists and if not, add it
        if not Admin.query.filter_by(created=True).first():
            admin_instance = Admin()
            db.session.add(admin_instance)
            db.session.commit()

    Limiter(app, default_limits=app.config.get('REQUEST_LIMITS'), key_func=get_remote_address)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=app.config.get('NUM_PROXIES'))

    app.register_blueprint(auth.blueprint)
    app.register_blueprint(users.blueprint)
    app.register_blueprint(admin.blueprint)

    CORS(app)

    return app


if __name__ == '__main__':
    so_auth = create_app()
    so_auth.run()
else:
    gunicorn_app = create_app()


