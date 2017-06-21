from __future__ import print_function
import boto3

print('Loading function')


def lambda_handler(event, context):
    config = boto3.client('organizations')
    account_list = config.list_accounts(
        MaxResults=10
    )
    my_json = {}
    for account in account_list['Accounts']:
        my_json[account['Id']] = account['Name']
    while 'NextToken' in account_list:
        account_list = config.list_accounts(
            NextToken=account_list['NextToken'],
            MaxResults=10
        )
        for account in account_list['Accounts']:
            my_json[account['Id']] = account['Name']

    return my_json
