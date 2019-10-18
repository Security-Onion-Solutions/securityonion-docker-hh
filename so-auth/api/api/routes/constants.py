from enum import Enum, auto

UNAUTHORIZED_ERR = 'Unauthorized'
INVALID_JSON_ERR = 'Invalid or missing JSON body'

JSON_ERROR_RESPONSE: dict = {
    'status': 'fail',
    'message': INVALID_JSON_ERR
}

UNHANDLED_EXCEPTION_RESPONSE: dict = {
    'status': 'fail',
    'message': 'Unhandled error, please try again'
}

LOGIN_FAIL_RESPONSE: dict = {
    'status': 'fail',
    'message': 'Incorrect username or password'
}


class TokenType(Enum):
    REFRESH = auto
    AUTH = auto
