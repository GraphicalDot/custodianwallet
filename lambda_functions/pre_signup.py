import json
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import uuid



CLIENT_ID = ''
CLIENT_SECRET = ''
USER_POOL_ID = ''


def lambda_handler(event, context):
    # TODO implement
    client = boto3.client('cognito-idp')
    try:
        email = event['request']['userAttributes']["email"]
    except:
        raise Exception("Email is  required")
        
    # try:
    #     preferred_username = event['request']['userAttributes']["preferred_username"]
    # except:
    #     raise Exception("Please provide preferred_username")
        
    emails = client.list_users(
    UserPoolId=USER_POOL_ID,
    AttributesToGet=[
        "email"
    ],
    Limit=10,
    Filter= "email = \"%s\""%(email),
    )
    
    #print (phone_numbers)
    if emails["Users"]:
        
        raise Exception("This email already exists")
    return event