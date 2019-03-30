import json


def validate(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps(event)
    }
