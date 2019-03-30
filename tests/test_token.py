import json
import jwt
import os
from unittest import TestCase, mock
from datetime import datetime, timedelta
from validate_token import validate


class TestToken(TestCase):
    def test_none_parameters(self):
        result = json.loads(validate(None, None))
        self.assertTrue(result.get('statusCode') == 401)

    def test_blank_parameters(self):
        result = json.loads(validate('', ''))
        self.assertTrue(result.get('statusCode') == 401)

    def test_access_token_not_jwt(self):
        event = {
            'access_token': '123'
        }
        result = json.loads(validate(event, ''))
        self.assertTrue(result.get('statusCode') == 401)

    def test_validate_bad_parameters(self):
        event = {
            "key1": "value1",
            "key2": "value2",
            "key3": "value3"
        }

        result = json.loads(validate(event, ''))
        self.assertTrue(result.get('statusCode') == 401)

    def test_access_token_invalid(self):
        with mock.patch.dict('os.environ', {'SECRET_KEY': '123456789'}):
            print(os.environ)
            payload = {
                'exp': datetime.utcnow() + timedelta(days=1),
                'iat': datetime.utcnow(),
                'sub': '1'
            }

            token = jwt.encode(
                payload,
                '987654321',
                algorithm='HS256'
            )

            event = {
                'access_token': token
            }

            result = json.loads(validate(event, ''))
            self.assertTrue(result.get('statusCode') == 401)

    def test_access_token_valid(self):
        with mock.patch.dict('os.environ', {'SECRET_KEY': '123456789'}):
            print(os.environ)
            payload = {
                'exp': datetime.utcnow() + timedelta(days=1),
                'iat': datetime.utcnow(),
                'sub': '1'
            }

            token = jwt.encode(
                payload,
                os.environ.get('SECRET_KEY'),
                algorithm='HS256'
            )

            event = {
                'access_token': token
            }

            result = json.loads(validate(event, ''))
            self.assertTrue(result.get('statusCode') == 200)
