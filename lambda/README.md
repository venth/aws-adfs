Contains a CloudFormation template to create a role and policy required 
for the function along with the function code. Currently the function 
and API are setup manually until we integrate building python, lambda, 
api gateway and cloudformation into our build pipeline.

Steps to deploy manually.
Create the lambda function
Create the gateway


Here is some automation around this process.
    
# Package the script
zip package.zip ./return_account_info.py

# Create a new function
aws lambda create-function \
    --function-name getAccountList \
    --runtime python2.7 \
    --role arn:aws:iam::865492507168:role/RoleAWSADFSListAcounts \
    --handler return_account_info.lambda_handler \
    --zip-file fileb://$PWD/package.zip \
    --region us-east-1
  
# Add permissions for API Gateway to execute the function
aws lambda add-permission \
    --region us-east-1 \
    --function-name getAccountList \
    --statement-id 1 \
    --principal apigateway.amazonaws.com \
    --action lambda:InvokeFunction \
    --source-arn arn:aws:execute-api:us-east-1:865492507168:<rest-api-id>/*/GET/

# Update the existing funtion
aws lambda update-function-code \
    --function-name getAccountList \
    --publish \
    --zip-file fileb://$PWD/package.zip  

# Deploy the api from swagger file. Work in progress or just create a 
# simple api with a GET method that points to the lambda function.
aws apigateway import-rest-api \
    --body file://$PWD/swagger.yml \
    --region us-east-1


python setup.py bdist_wheel --universal
