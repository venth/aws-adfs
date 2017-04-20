# aws-adfs
[![PyPI version](https://badge.fury.io/py/aws-adfs.svg)](https://badge.fury.io/py/aws-adfs)
[![Travis build](https://api.travis-ci.org/venth/aws-adfs.svg?branch=master)](https://api.travis-ci.org/venth/aws-adfs.svg?branch=master)

Command line tool to easier aws cli authentication against ADFS (multi factor authentication with active directory).

Thanks to [Brandond](https://github.com/brandond) contribution - "Remove storage of credentials, in favor of storing ADFS session cookies"
aws-adfs:

> allows you to re-login to STS without
> entering credentials for an extended period of time, without having to store the user's actual credentials.
> It also lets an organization control the period in which a user can re-login to STS without entering credentials,
> by altering the ADFS session lifetime.

Thanks to [Brandond](https://github.com/brandond) contribution - "Add support for legacy aws_security_token key in credentials file"
aws-adfs supports ansible by providing two keys with security token:
* AWS_SESSION_TOKEN and
* AWS_SECURITY_TOKEN

Thanks to [Brandond](https://github.com/brandond) contribution - "Add support for Kerberos SSO on Windows via requests_negotiate_sspi"
* on windows os will be used Security Support Provider Interface

# Compatibility

As of version 0.2.0, this tool acts on the 'default' profile unless an alternate profile name has been specified on the command line or in your environment. Previous versions acted on the 'adfs' profile by default.

# MFA integration

aws-adfs integrates with:
* [duo security](https://duo.com) MFA provider

# Installation

* user local installation

    ```
    pip install aws-adfs
    ```

    Please note, that you need to add $HOME/.local/bin to your PATH

* system wide installation

    ```
    sudo pip install aws-adfs
    ```

* virtualenvs

    ```
    virtualenv -p /usr/bin/python2.7 aws-adfs
    source aws-adfs/bin/activate
    pip install aws-adfs
    ...
    ...
    deactivate
    ```

# Examples of usage

* login to your adfs host with disabled ssl verification on aws cli profile: adfs

    ```
    aws-adfs login --adfs-host=your-adfs-hostname --no-ssl-verification
    ```

    and verification

    ```
    aws --profile=adfs s3 ls
    ```

* login to your adfs host with disabled ssl verification on specified aws cli profile: specified-profile

    ```
    aws-adfs login --profile=specified-profile --adfs-host=your-adfs-hostname --no-ssl-verification
    ```

    and verification

    ```
    aws --profile=specified-profile s3 ls
    ```

* help, help, help?
    ```
    $ aws-adfs --help
    Usage: aws-adfs [OPTIONS] COMMAND [ARGS]...

    Options:
      --version  Show current tool version
      --help  Show this message and exit.

    Commands:
      list   lists available profiles
      login  Authenticates an user with active directory...
      reset  removes stored profile
    ```

    ```
    $ aws-adfs list --help
    Usage: aws-adfs list [OPTIONS]

      lists available profiles

    Options:
      --version  Show current tool version
      --help  Show this message and exit.
    ```

    ```
    $ aws-adfs login --help
    Usage: aws-adfs login [OPTIONS]
    
      Authenticates an user with active directory credentials
    
    Options:
      --profile TEXT                  AWS cli profile that will be authenticated.
                                      After successful authentication just use:
                                      aws --profile <authenticated profile>
                                      <service> ...
      --region TEXT                   The default AWS region that this script will
                                      connect
                                      to for all API calls
      --ssl-verification / --no-ssl-verification
                                      SSL certificate verification: Whether or not
                                      strict certificate
                                      verification is done,
                                      False should only be used for dev/test
      --adfs-host TEXT                For the first time for a profile it has to
                                      be provided, next time for the same profile
                                      it will be loaded from the stored
                                      configuration
      --output-format [json|text|table]
                                      Output format used by aws cli
      --provider-id TEXT              Provider ID, e.g urn:amazon:webservices
                                      (optional)
      --s3-signature-version [s3v4]   s3 signature version: Identifies the version
                                      of AWS Signature to support for
                                      authenticated requests. Valid values: s3v4
      --help                          Show this message and exit.

    ```
    ```
    $ aws-adfs reset --help                                                                                                                                              13:39
    Usage: aws-adfs reset [OPTIONS]

      removes stored profile

    Options:
      --profile TEXT  AWS cli profile that will be removed
      --help          Show this message and exit.
    ```

# Known issues
* in cases of trouble with lxml please install

  ```
  sudo apt-get install python-dev libxml2-dev libxslt1-dev zlib1g-dev
  ```
* python 2.6 is not supported
* python 3.2 is not supported


# Credits
* [Brandond](https://github.com/brandond) for: Remove storage of credentials, in favor of storing ADFS session cookies
* [Brandond](https://github.com/brandond) for: Add support for legacy aws_security_token key in credentials file
* [Brandond](https://github.com/brandond) for: Store last username in profile config; use it as default for prompt
* [Brandond](https://github.com/brandond) for: python 3 compatibility
* [Brandond](https://github.com/brandond) for: Add support for Kerberos SSO on Windows via requests_negotiate_sspi
* [Brandond](https://github.com/brandond) for: ssl_verification must be a str
* [Brandond](https://github.com/brandond) for: Move pytest-runner out of setup-requires
* [Brandond](https://github.com/brandond) for: Improve handling of role selection
* [Brandond](https://github.com/brandond) for: Improve handling of errors caused by excessive cookie growth
* [Brandond](https://github.com/brandond) for: Default to 'default' profile, in line with other AWS tools
* [kwhitlock](https://github.com/kwhitlock) for: Added extra option "--provider-id"
* [SydOps](https://github.com/SydOps) for: add additional information in list command's output
* [eric-nord](https://github.com/eric-nord) for: bringing topic of [duo security](https://duo.com) MFA integration
