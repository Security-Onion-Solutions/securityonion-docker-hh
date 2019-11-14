from datetime import datetime
from functools import wraps
from flask import request, jsonify, make_response, current_app as app

from models import db
from models.user import User
from routes.constants import JSON_ERROR_RESPONSE, UNHANDLED_EXCEPTION_RESPONSE


def requires_token(token_type: str):
    """
     Decorator to require auth or refresh token for a route
    :param token_type: TokenType enum
    :return: function
    """

    def __requires_token__(f):
        """
        :param f: function
        :return: function
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                if token_type == 'refresh':
                    token: str = request.cookies.get('Refresh-Token', None)
                else:
                    token: str = request.cookies.get('Auth-Token', None)
                if token is None:
                    return jsonify({
                        'message': 'Could not read cookie from request',
                        'status': 'fail'
                    }), 500
                check_token_result = __check_token__(token, token_type)
                if type(check_token_result) == tuple:
                    res = make_response(check_token_result)
                    res.headers['Location'] = f'{app.config["BASE_PATH"]}/auth/renew'
                    return res
                else:
                    args = args + (check_token_result.get('id'),)
                    return f(*args, **kwargs)
            except Exception as e:  # pragma: no cover
                app.logger.error(e)
                return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500

        return decorated

    return __requires_token__


def requires_localhost(f):
    """
    Require the remote address to be the same as the requesting ip address
    :param f: decorated function
    :return: function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            rem_addr = request.remote_addr
            if rem_addr == '127.0.0.1':
                return f(*args, **kwargs)
            else:
                return jsonify({
                    'status': 'fail',
                    'message': 'This endpoint requires an SSH tunnel in order to be called',
                }), 401
        except Exception as e:  # pragma: no cover
            app.logger.error(e)
            return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500

    return decorated


def __check_token__(token: str, token_type: str):
    """
    Checks given token and returns a response if the process fails
    :param token: string
    :return: http_response
    """
    if token_type == 'refresh':
        token_decode = User.decode_token(token, is_refresh=True)
    else:
        token_decode = User.decode_token(token)
    valid_jwt_token = token_decode.get('id', False)
    if not valid_jwt_token:
        app.logger.error(f'Received invalid token')

        return jsonify({
            'status': 'fail',
            'message': token_decode.get('message')
        }), int(token_decode.get('error_code'))
    else:
        user = User.query.filter_by(id=token_decode['id']).first()
        if not user:
            app.logger.error(f'Token for non-existent user received')
            return jsonify(JSON_ERROR_RESPONSE), 403
        username = user.username
        if not user.logged_in:
            app.logger.error(f'User {username} tried to use a token without being logged in')
            return jsonify({
                'status': 'fail',
                'message': 'User not logged in, please log in'
            }), 401
        else:
            user.last_contact = datetime.now()
            return token_decode


def save_model(db_model):
    db.session.add(db_model)
    db.session.commit()

