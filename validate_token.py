import json
import os
import jwt
import logging


status_codes = {
    'success': 200,
    'unauthorized': 401,
}

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class AuthenticationResponse(json.JSONEncoder):
    def __init__(self, statusCode, token='', message=''):
        self.statusCode = statusCode
        self.token = token
        self.message = message

    def default(self, instance):
        if isinstance(instance, AuthenticationResponse):
            return {
                'statusCode': instance.statusCode,
                'token': instance.token,
                'message': instance.message
            }
        else:
            return json.JSONEncoder.default(self, instance)


def validate(event, context):
    try:
        logging.info(f'Received event: {event} context: {context}')
        response = None
        token = event.get('headers').get('Authorization')[7:]

        if token:
            response = AuthenticationResponse(
                statusCode=status_codes.get('success'),
                token=validate_token(token)
            )
    except Exception as err:
        logging.error(err, exc_info=True)
        response = AuthenticationResponse(
            statusCode=status_codes.get('unauthorized')
        )
    finally:
        if response is None:
            response = AuthenticationResponse(
                statusCode=status_codes.get('unauthorized')
            )
        result = json.dumps(response, default=response.default)
        logging.info(f'Response: {result}')
        return result


def validate_token(token):
    return jwt.decode(
        jwt=token,
        key=os.environ.get('SECRET_KEY'),
        algorithms=['HS256'])
