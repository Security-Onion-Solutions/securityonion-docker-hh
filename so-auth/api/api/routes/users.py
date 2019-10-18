from re import match
from flask import Blueprint, request, jsonify, current_app as app

from models.user import User
from routes.constants import *
from routes.utils import save_model

blueprint = Blueprint('users', __name__, url_prefix='/users')


# NOT IMPLEMENTED
"""
@blueprint.route('/', methods=['GET'], strict_slashes=False)
@requires_token(token_type='auth')
@requires_localhost
def list_users(*_):  # pragma: no cover
    try:
        user_list: list = User.query.all()
        if len(user_list) == 0:
            return jsonify({
                'status': 'success',
                'message': 'No users exist'
            }), 400

        user_info_list: list = []
        for user in user_list:
            user_info_list.append({
                'username': user.username,
                'attributes': {
                    'logged_in': user.logged_in
                }
            })
        app.logger.info('Retrieved list of all users')
        return jsonify({
            'status': 'success',
            'content': user_info_list
        }), 200

    except Exception as e:
        app.logger.error(e)
        return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500
"""


# NOT IMPLEMENTED
"""
@blueprint.route('/single', methods=['GET'])
@requires_token(token_type='auth')
def get_single_user(*_):  # pragma: no cover
    try:
        content: dict = request.get_json(silent=True)

        username: str = content.get('username')

        user = User.query.filter_by(username=username).first()
        if user is None:
            return jsonify({
                'status': 'fail',
                'message': f'User {username} does not exist'
            }), 400

        response = {
            'status': 'success',
            'attributes': {
                'logged_in': user.logged_in
            }
        }

        return jsonify(response), 200

    except Exception as e:
        app.logger.error(e)
        return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500
"""


@blueprint.route('/change_password', methods=['PUT'])
def change_password():
    try:
        content: dict = request.get_json(silent=True)

        user: User = User.query.filter_by(username=content.get('username')).first()
        old_password = content.get('old_password')
        if old_password is None:
            return jsonify(JSON_ERROR_RESPONSE), 400
        if not user.check_password(old_password):
            app.logger.error(f'User {user.username} failed to change password')
            user.failed_login_attempts += 1
            save_model(user)
            return jsonify(LOGIN_FAIL_RESPONSE), 401
        else:
            new_password = content.get('new_password')
            if new_password is None:
                return jsonify(JSON_ERROR_RESPONSE), 400
            if not match(app.config.get('PASSWORD_REGEX'), new_password):
                return jsonify({
                    'status': 'fail',
                    'message': 'Password must be at least 6 characters'
                }), 400
            user.change_password(new_password)
            save_model(user)

            message: str = f'Password changed for user {user.username}'
            app.logger.info(message)
            return jsonify({
                'status': 'success',
                'message': message
            }), 200
    except Exception as e:  # pragma: no cover
        app.logger.error(e)
        return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500


# NOT IMPLEMENTED
""""
@blueprint.route('/change_username', methods=['PUT'])
@requires_token(token_type='auth')
def update_username(user_id):  # pragma: no cover
    try:
        content: dict = request.get_json(silent=True)

        new_username = content.get('new_username')
        if new_username is None:
            return jsonify(JSON_ERROR_RESPONSE), 400

        user: User = User.query.filter_by(id=user_id).first()

        proposed_user = User.query.filter_by(username=new_username).first()
        if proposed_user is not None:
            return jsonify({
                'status': 'fail',
                'message': f'User {new_username} already exists'
            }), 400
        else:
            user.username = new_username

        save_model(user)

        message: str = f'User {user.username} changed username to {new_username}'
        app.logger.info(message)
        return jsonify({
            'status': 'success',
            'message': message
        }), 200

    except Exception as e:
        app.logger.error(e)
        return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500
"""

# NOT IMPLEMENTED
"""
@blueprint.route('/delete', methods=['DELETE'])
@requires_token(token_type='auth')
def delete_user(user_id):  # pragma: no cover
    try:
        user: User = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify({
                'status': 'fail',
                'message': 'User does not exist'
            }), 400

        db.session.delete(user)
        db.session.commit()

        message: str = f'User {user.username} deleted'
        app.logger.info(message)
        return jsonify({
            'status': 'success',
            'message': message
        }), 200

    except Exception as e:
        app.logger.error(e)
        return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500
"""
