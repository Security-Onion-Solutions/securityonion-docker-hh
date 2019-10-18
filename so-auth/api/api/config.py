import os
import re
from base64 import b64encode


class BaseConfig(object):
    APP_NAME = 'SO Auth'

    # Docker information
    BASE_PATH = os.environ.get('BASE_PATH', '')

    # Generate secret key if none exists. Then either way, read in that key.
    if os.path.exists('secret') and os.path.isfile:
        with open('secret') as f:
            SECRET_KEY = f.read()
    else:
        SECRET_KEY = b64encode(os.urandom(16)).decode('utf-8')
        with open('secret', 'w') as f:
            f.write(SECRET_KEY)

    # User token settings
    REFRESH_TOKEN_TIMEOUT = int(os.environ.get('REFRESH_TOKEN_TIMEOUT', 30))  # this is in days
    AUTH_TOKEN_TIMEOUT = int(os.environ.get('AUTH_TOKEN_TIMEOUT', 30))  # this is in minutes

    # ORM config
    SQLALCHEMY_DATABASE_URI = os.environ.get('DB_URI', 'sqlite:///db.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # General Flask Settings
    NUM_PROXIES = int(os.environ.get('NUM_PROXIES', 1))
    CSRF_ENABLED = True
    REQUEST_LIMITS = ['4/second', '60/minute', '600/hour']

    PASSWORD_REGEX = re.compile('(?=.{6,})')


class DevelopConfig(BaseConfig):
    DOMAIN = 'localhost'
    HOMEPAGE = 'http://localhost:8080'
    BASE_PATH = ''
    NUM_PROXIES = 0


