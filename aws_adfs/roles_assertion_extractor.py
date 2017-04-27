import base64
import click
import lxml.etree as ET
import requests

default_session_duration = 3600


def extract(html):
    assertion = None

    # Check to see if login returned an error
    # Since we're screen-scraping the login form, we need to pull it out of a label
    for element in html.findall('.//form[@id="loginForm"]//label[@id="errorText"]'):
        if element.text is not None:
            click.echo('Login error: {}'.format(element.text), err=True)
            exit(-1)

    # Retrieve Base64-encoded SAML assertion from form SAMLResponse input field
    for element in html.findall('.//form[@name="hiddenform"]/input[@name="SAMLResponse"]'):
        assertion = element.get('value')

    # If we did not get an error, but also do not have an assertion,
    # then the user needs to authenticate
    if not assertion:
        return None, None, None

    # Parse the returned assertion and extract the authorized roles
    saml = ET.fromstring(base64.b64decode(assertion))

    # Find all roles offered by the assertion
    raw_roles = saml.findall(
        './/{*}Attribute[@Name="https://aws.amazon.com/SAML/Attributes/Role"]/{*}AttributeValue'
    )
    aws_roles = [element.text.split(',') for element in raw_roles]

    # Note the format of the attribute value is provider_arn, role_arn
    principal_roles = [role for role in aws_roles if ':saml-provider/' in role[0]]

    # File contains a list of AWS account id's and names
    # map_file = requests.get('https://s3.amazonaws.com/eis-aws-accounts/account_map.json')
    map_file = requests.get('https://aafn.ebsco.cloud')

    account_map = map_file.json()

    for index, principal_arn in enumerate(principal_roles):
        account_id = principal_arn[0].split('::')[1].split(':')[0]

        if account_id not in account_map:
            principal_roles[index].append(account_id)
        else:
            account_name = account_map[account_id]
            principal_roles[index].append(account_name)

    aws_session_duration = default_session_duration
    # Retrieve session duration
    for element in saml.findall(
            './/{*}Attribute[@Name="https://aws.amazon.com/SAML/Attributes/SessionDuration"]/{*}AttributeValue'
    ):
        aws_session_duration = int(element.text)

    return principal_roles, assertion, aws_session_duration

