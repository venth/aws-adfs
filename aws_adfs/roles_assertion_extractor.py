import base64
import click
import lxml.etree as ET


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

    # If we did not get an error, but also do not have an assertion, then the user needs to authenticate
    if not assertion:
        return None, None

    # Parse the returned assertion and extract the authorized roles
    saml = ET.fromstring(base64.b64decode(assertion))

    # Find all roles offered by the assertion
    raw_roles = saml.findall('.//{*}Attribute[@Name="https://aws.amazon.com/SAML/Attributes/Role"]/{*}AttributeValue')
    aws_roles = [element.text.split(',') for element in raw_roles]

    # Note the format of the attribute value is provider_arn, role_arn
    principal_roles = [role for role in aws_roles if ':saml-provider/' in role[0]]

    return principal_roles, assertion
