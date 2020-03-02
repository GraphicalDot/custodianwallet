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
    dynamodb = boto3.resource('dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_URL)
    table = dynamodb.Table(TABLE_NAME)
    for field in ["username", "encryptedMnemonicPhrase", "eth_address"]:
        if event.get(field) is None:
            return  {"error": True, "success": False, "message": f"{field} is required", "data": None}
    
    username = event["username"]    
    try:
        response = table.update_item(
                Key={"username": event['username']},
                
                UpdateExpression='SET encryptedMnemonicPhrase=:encryptedMnemonicPhrase, eth_address=:eth_address',
                ExpressionAttributeValues={
                        ':encryptedMnemonicPhrase': event["encryptedMnemonicPhrase"],
                        ':eth_address': event["eth_address"],
                    },
              
            )



    except Exception as e:
        return {"error": True, "success": False, "message": f"Error in updating user {e.__str__()}", "data": None}

    return {"error": False, "success": True, "message": "user successfully updated", "data": None}
