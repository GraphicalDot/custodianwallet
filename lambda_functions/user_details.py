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
DYNAMODB_URL = "http://dynamodb.us-west-2.amazonaws.com"
DYNAMODB_REGION = "us-west-2"
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
    user_id = str(uuid.uuid4())
    dynamodb = boto3.resource('dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_URL)
    table = dynamodb.Table(TABLE_NAME)
    
    
    for key in ['KDF', 'asymmetricPublicKey','encryptedAsymmetricPrivateKey', 'encryptedEncryptionKey', 'iterations', 'passwordDerivedKeyHash', 'passwordHash']:
        if not event.get(key):
            return {"error": True, "success": False, "message": f"{key} is required", "data": None}
    try:
        response = table.get_item(
            Key={
                'username': event["username"]
            }
        )
        if response.get("Item").get("asymmetricPublicKey"):
            return {"error": True, "success": False, "message": "User already exists", "data": None}
        else:
          response = table.update_item(
                Key={"username": event['username']},
                
                UpdateExpression='SET kdf=:kdf, asymmetricPublicKey=:asymmetricPublicKey, encryptedEncryptionKey=:encryptedEncryptionKey,encryptedAsymmetricPrivateKey=:encryptedAsymmetricPrivateKey, passwordDerivedKeyHash=:passwordDerivedKeyHash, passwordHash=:passwordHash, iterations=:iterations',
                ExpressionAttributeValues={
                        ':kdf': event["KDF"],
                        ':asymmetricPublicKey': event["asymmetricPublicKey"],
                        ":encryptedEncryptionKey": event["encryptedEncryptionKey"],
                        ':encryptedAsymmetricPrivateKey': event["encryptedAsymmetricPrivateKey"],
                        ':iterations': event["iterations"],
                        ':passwordDerivedKeyHash': event["passwordDerivedKeyHash"],
                        ':passwordHash': event["passwordHash"],
                    },
              
            )
  

    except Exception as e:
        return {"error": True, "success": False, "message": e.__str__() }
    
    return {"error": False, "success": True, "message": "User successfully created", "data": None}
