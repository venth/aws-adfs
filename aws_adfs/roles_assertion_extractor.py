import base64
import itertools

import lxml.etree as ET


def extract(html):
    assertion = None

    # Check to see if login returned an error
    # Since we're screen-scraping the login form, we need to pull it out of a label
    for element in html.findall('.//form[@id="loginForm"]//label[@id="errorText"]'):
        if element.text is not None:
            raise RuntimeError('Login error. The error: {}'.format(element.text))

    # Retrieve Base64-encoded SAML assertion from form SAMLResponse input field
    for element in html.findall('.//form[@name="hiddenform"]/input[@name="SAMLResponse"]'):
        assertion = element.get('value')

    # If we did not get an error, but also do not have an assertion, then the user needs to authenticate
    if not assertion:
        return None, None

    # Parse the returned assertion and extract the authorized roles
    saml = ET.fromstring(base64.b64decode(assertion))

    aws_roles = map(
        lambda saml2attributevalue: saml2attributevalue.text,
        itertools.chain.from_iterable(
            map(
                lambda saml2attribute: list(
                    saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')),
                filter(
                    lambda saml2attribute: saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role',
                    saml.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')
                ),
            )
        )
    )

    # Note the format of the attribute value is principal_arn, role_arn
    principal_roles = list(map(
        lambda chunks: (chunks[0], chunks[1]),
        filter(
            lambda chunks: 'saml-provider' in chunks[0],
            map(
                lambda role: role.split(','),
                aws_roles,
            )
        )
    ))

    return principal_roles, assertion
