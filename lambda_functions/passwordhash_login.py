import json
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import uuid
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr

import decimal
DYNAMODB_URL = ""
DYNAMODB_REGION = ""
TABLE_NAME = ""
# Helper class to convert a DynamoDB item to JSON.
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if abs(o) % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)



def lambda_handler(event, context):
    # TODO implement
    if not event.get("username"):
        return {"error": True, "success": False, "message": "username is required", "data": None}
    
    dynamodb = boto3.resource('dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_URL)
    table = dynamodb.Table(TABLE_NAME)
    response = table.get_item(
        Key={
            'username': event["username"],
            
        },
        AttributesToGet=["encryptedEncryptionKey", "passwordHash", "encryptedAsymmetricPrivateKey"]
    )
    

    if not response.get("Item"):
        print (response.get("Item"))
        return {"error": True, "success": False, "message": "User Doesnt exists", "data": None}
    
    
    if response.get("Item").get("passwordHash") != event["passwordHash"]:
        return {"error": True, "success": False, "message": "passwordHash doesnt match", "data": None}

    response["Item"].pop("passwordHash")
    return {"error": False, "success": True, "message": "Users successfully logged in", "data": response["Item"]}

