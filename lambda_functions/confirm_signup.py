import json
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import uuid

import decimal


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
    for field in ["username",  "code"]:
        if not event.get(field):
            return {"error": False, "success": True, 'message': f"{field} is not present", "data": None}

    
    try:
        
        username = event['username']
        code = event['code']

        response = client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            ConfirmationCode=code,
            ForceAliasCreation=False,
            # AnalyticsMetadata={
            #     'AnalyticsEndpointId': 'string'
            # },
            # UserContextData={
            #     'EncodedData': 'string'
            # }
             )
        print (response)

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
    response = client.admin_get_user(
            UserPoolId=USER_POOL_ID,
            Username=event["username"]
        )

    #Getting user from cognito pool from the username and passing this user to the userDetailsDynamoDB lambda function 
    user = {}
    user.update({"username": response.get("Username")})
    for point in response.get("UserAttributes"):
        user.update({point.get("Name"): point.get("Value")})

    lambda_client = boto3.client('lambda', region_name='us-west-2')
    invoke_response = lambda_client.invoke(FunctionName="custodian_wallet_insert_user",
                                           InvocationType='RequestResponse',
                                           Payload=json.dumps(user))
    response_payload = json.loads(invoke_response['Payload'].read().decode("utf-8"))
    print (response_payload)
    return {"error": False, "success": True, "message": f"The user has been confirmed, Please sign in"}