import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import json




CLIENT_ID = ''
CLIENT_SECRET = ''
USER_POOL_ID = ''

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'), 
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


def lambda_handler(event, context):
    client = boto3.client('cognito-idp')
    
    for field in ["username", "password"]:
        if not event.get(field):
            
            return {'message': f"{field} is required", "error": True, "success": False, "data": None}    
    
    secret_hash = get_secret_hash(event["username"])

    
    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': event["username"],
                'SECRET_HASH': secret_hash,
                'PASSWORD': event["password"],
             
            },
            #these will be passed to preauthentication lambda function as it is
            ClientMetadata={
                'username': event["username"],
                'password': event["password"], 
            })
        user_dict = {}
        user = client.admin_get_user(
             UserPoolId=USER_POOL_ID,
            Username=event["username"])
        [user_dict.update({e['Name']: e['Value']}) for e in user['UserAttributes']]
        user_dict.update({"created_at": user["UserCreateDate"]})
        print (user_dict)
    except client.exceptions.NotAuthorizedException:
        return {"error": True, "success": False, 'message': "The username or password is incorrect", "data": None}

    except client.exceptions.UserNotConfirmedException:
        return {"error": True, "success": False, 'message': "User is not confirmed", "data": None}

    
    if resp.get("AuthenticationResult"):
        return {'message': "success", "error": False, "success": True, "data": {"name": user_dict["name"], 
            "email": user_dict["email"], "created_at": user_dict["created_at"].strftime("%d-%m-%Y"), "username": event["username"],
            "id_token": resp["AuthenticationResult"]["IdToken"], "refresh_token": resp["AuthenticationResult"]["RefreshToken"],
            "access_token": resp["AuthenticationResult"]["AccessToken"], "expires_in": resp["AuthenticationResult"]["ExpiresIn"],
            "token_type": resp["AuthenticationResult"]["TokenType"]
        }}
    else:
        
        return {"error": False, "success": True, "data": {"challenge_name": resp["ChallengeName"], "session_token": resp["Session"], "challenge_parameters": resp["ChallengeParameters"] }}
