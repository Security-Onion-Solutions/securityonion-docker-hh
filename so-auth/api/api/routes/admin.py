from flask import Blueprint, current_app as app, jsonify

from api.models.admin import Admin
from api.routes.constants import UNHANDLED_EXCEPTION_RESPONSE

BLUEPRINT = Blueprint('admin', __name__, url_prefix='/admin')


@BLUEPRINT.route('/first_run', methods=['POST'])
def check_first_run():
    try:
        admin_settings: Admin = Admin.query.filter_by(created=True).first()
        return jsonify({
            'status': 'success',
            'first_run': admin_settings.first_run
        })
    except Exception as e:  # pragma: no cover
        app.logger.error(e)
        return jsonify(UNHANDLED_EXCEPTION_RESPONSE), 500
