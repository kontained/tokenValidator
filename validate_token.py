import json
import os
import jwt


status_codes = {
    'success': 200,
    'unauthorized': 401,
}


class AuthenticationResponse(json.JSONEncoder):
    def __init__(self, statusCode, token='', message=''):
        self.statusCode = statusCode
        self.token = token
        self.message = message
    
    def default(self, instance):
        if  isinstance(instance, AuthenticationResponse):
            return {
                'statusCode': instance.statusCode,
                'token': instance.token,
                'message': instance.message
            }
        else:
            return json.JSONEncoder.default(self, instance)


class TestEncoder(json.JSONEncoder):
    pass

def validate(event, context):
    try:
        response = None
        if event.get('access_token'):
            response = AuthenticationResponse(
                statusCode=status_codes.get('success'),
                token=validate_token(event.get('access_token'))
            )
        elif event.get('refresh_token'):
            response = AuthenticationResponse(
                statusCode=status_codes.get('success'),
                token=validate_token(event.get('refresh_token'))
            )
    except:
        response = AuthenticationResponse(
            statusCode=status_codes.get('unauthorized')
        )
    finally:
        if response is None:
            response = AuthenticationResponse(
                statusCode=status_codes.get('unauthorized')
            ), 
        return json.dumps(response, default=response.default)


def validate_token(token):
    return jwt.decode(
        jwt=token,
        key=os.environ.get('SECRET_KEY'),
        algorithms=['HS256'])
