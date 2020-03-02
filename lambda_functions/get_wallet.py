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
        AttributesToGet=["encryptedMnemonicPhrase", "passwordHash", "encryptedAsymmetricPrivateKey"]
    )
    

    if not response.get("Item"):
        print (response.get("Item"))
        return {"error": True, "success": False, "message": "User Doesnt exists", "data": None}
    
    
    # if response.get("Item").get("passwordHash") != event["passwordHash"]:
    #     return {"error": True, "success": False, "message": "passwordHash doesnt match", "data": None}

    response["Item"].pop("passwordHash")
    return {"error": False, "success": True, "message": "success", "data": response["Item"]}
