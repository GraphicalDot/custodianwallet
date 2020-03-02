

Serverless Custodian wallet for Ethereum inspired by Portis whitepaper

It uses AWS cognito identity pool, Lambda functions, API gateway.

If you are not familiar with implementing Serverless architecture in python using cognito, API gateway, Lambda function visit.

https://medium.com/@houzier.saurav/aws-cognito-with-python-6a2867dd02c6
https://medium.com/@houzier.saurav/authentication-with-cognito-202977f8d64e
https://medium.com/analytics-vidhya/private-api-endpoints-with-api-gateway-authorizers-and-cognito-249c288b0ab8


Link to portis whitepaper
https://assets.portis.io/white-paper/latest.pdf


Requirements:
    A table on DynamoDB which will keep all the users data in encrypted format.

Replace your Amazon gateway id in settings.py file. You can use design your own URL schema at API gateway or 
you can use the mentioned in settings.py file.


Start running the functions in user_apis.py file.
Forgot password flow hasnt been implemented yet.




