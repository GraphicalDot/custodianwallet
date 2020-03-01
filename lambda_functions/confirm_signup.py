import json
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import uuid
import datetime
import decimal
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr

CLIENT_ID = ''
CLIENT_SECRET = ''
USER_POOL_ID = ''
DYNAMODB_URL = ""
DYNAMODB_REGION = ""
TABLE_NAME = ""

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2




def lambda_handler(event, context):
    client = boto3.client('cognito-idp')

    check_keys(event)
        
    
    try:
        
        username = event['username']
        code = event['code']

        response = client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            ConfirmationCode=code,
            ForceAliasCreation=False,
           
             )

    except client.exceptions.UserNotFoundException as e:
        return {"error": True, "success": False, "message": "Username doesnt exists"}
        
    except client.exceptions.CodeMismatchException as e:
        return {"error": True, "success": False, "message": "Invalid Verification code"}
        
    except client.exceptions.NotAuthorizedException as e:
        return {"error": True, "success": False, "message": "User is already confirmed"}
    
    except client.exceptions.LimitExceededException as e:
        return {"error": True, "success": False, "message": "Attempt limit exceeded, please try after some time"}
        

    
    except Exception as e:
        return {"error": True, "success": False, "message": f"Uknown error {e.__str__()} "}
    
 
    return insert_user(client, event)


def check_keys(event):
    for key in ['username', 'KDF', 'code', 'asymmetricPublicKey','encryptedAsymmetricPrivateKey', 'encryptedEncryptionKey', 'iterations', 'passwordDerivedKeyHash', 'passwordHash']:
        if not event.get(key):
            return {"error": True, "success": False, "message": f"{key} is required", "data": None}
    return
    
def insert_user(client, event):
    response = client.admin_get_user(
            UserPoolId=USER_POOL_ID,
            Username=event["username"]
        )

    #Getting user from cognito pool from the username and passing this user to the userDetailsDynamoDB lambda function 
    
    user = {}
    # user.update({"username": event.get("username")})
    for point in response.get("UserAttributes"):
        user.update({point.get("Name"): point.get("Value")})
    
    
    user.update({"created_at": datetime.now().strftime("%d-%m-%Y"),
                "kdf": event["KDF"],
                "username": event["username"],
                "asymmetricPublicKey": event["asymmetricPublicKey"],
                "encryptedEncryptionKey": event["encryptedEncryptionKey"],
                "encryptedAsymmetricPrivateKey": event["encryptedAsymmetricPrivateKey"],
                "iterations": event["iterations"],
                "passwordDerivedKeyHash": event["passwordDerivedKeyHash"],
                "passwordHash": event["passwordHash"]})
    
    print (user)
    dynamodb = boto3.resource('dynamodb', region_name=DYNAMODB_REGION, endpoint_url=DYNAMODB_URL)
    table = dynamodb.Table(TABLE_NAME)
    try:
        response = table.put_item(
              Item=user
            )
        return {"error": False, "success": True, "message": f"The user has been confirmed, Please login again", "data": None}    
    except Exception as e:
        return {"error": True, "success": False, "message": f"The user cannot be updated to dynamodb because of {e.__str__()}", "data": None}