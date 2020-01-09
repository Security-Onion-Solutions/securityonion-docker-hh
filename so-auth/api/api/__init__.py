import os

from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from api.models import DB
from api.models.admin import Admin
from api.routes import users, auth, admin


def create_app():
    app = Flask(__name__)

    if app.env == 'development':
        app.config.from_object('api.config.DevelopConfig')
    else:
        app.config.from_object('api.config.BaseConfig')

    # init ORM
    with app.app_context():
        DB.init_app(app)
        DB.create_all()

        db_uri = str(app.config.get('SQLALCHEMY_DATABASE_UR'))
        if db_uri.startswith('sqlite:////'):
            os.chmod(db_uri.replace('sqlite:////', ''), 0o600)

        # check if admin entry already exists and if not, add it
        if not Admin.query.filter_by(created=True).first():
            admin_instance = Admin()
            DB.session.add(admin_instance)
            DB.session.commit()

    # Request limiter was causing issues with Kibana setup, disabling for now
    # Limiter(app, default_limits=app.config.get('REQUEST_LIMITS'), key_func=get_remote_address)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=app.config.get('NUM_PROXIES'))

    app.register_blueprint(auth.BLUEPRINT)
    app.register_blueprint(users.BLUEPRINT)
    app.register_blueprint(admin.BLUEPRINT)

    CORS(app)

    return app


if __name__ == '__main__':
    SO_AUTH = create_app()
    SO_AUTH.run()
else:
    GUNICORN_APP = create_app()
