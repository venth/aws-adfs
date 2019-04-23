# aws-adfs
[![PyPI version](https://badge.fury.io/py/aws-adfs.svg)](https://badge.fury.io/py/aws-adfs)
[![Travis build](https://api.travis-ci.org/venth/aws-adfs.svg?branch=master)](https://api.travis-ci.org/venth/aws-adfs.svg?branch=master)

The project provides command line tool - `aws-adfs` to ease aws cli authentication against ADFS (multi factor authentication with active directory) and

## `aws-adfs` command line tool
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

### Compatibility

As of version 0.2.0, this tool acts on the 'default' profile unless an alternate profile name has been specified on the command line or in your environment. Previous versions acted on the 'adfs' profile by default.

### MFA integration

aws-adfs integrates with:
* [duo security](https://duo.com) MFA provider
* [Symantec VIP](https://vip.symantec.com/) MFA provider
* [RSA SecurID](https://www.rsa.com/) MFA provider

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

## `aws-adfs`
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

* login to your adfs host within ansible playbook

    ```
    ---
    - name: "Auth sts aws"
      command: "aws-adfs login --adfs-host sts.example.com --env --stdout --role-arn arn:aws:iam::000123456789:role/ADMIN"
      register: sts_result
      environment:
        - username: "{{ ansible_user }}@example.com"
        - password: "{{ ansible_ssh_pass }}"
    
    - name: "Set sts facts"
      set_fact:
        sts: "{{ sts_result.stdout | from_json }}"
    
    - name: "List s3 Buckets"
      aws_s3_bucket_facts:
        aws_access_key: "{{ sts.AccessKeyId }}"
        aws_secret_key: "{{ sts.SecretAccessKey }}"
        security_token: "{{ sts.SessionToken }}"
        region: "us-east-1"
      register: buckets
    
    - name: "Print Buckets"
      debug:
        var: buckets
    ```

* login to your adfs host by passing username and password credentials via a file

    ```
    aws-adfs login --adfs-host=your-adfs-hostname --authfile=/path/and/file/name
    ```

    Auth file should be in format of

    ```
    [profile_name]
    username = your_username
    password = your_password
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
      --adfs-ca-bundle TEXT           Override CA bundle for SSL certificate
                                      verification for ADFS server only.
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
      --env                           Read username, password from environment
                                      variables (username and password).
      --stdin                         Read username, password from standard input
                                      separated by a newline.
      --authfile TEXT                 Read username, password from a local file
                                      (optional)
      --stdout                        Print aws_session_token in json on stdout.
      --printenv                      Output commands to set AWS_ACCESS_KEY_ID,
                                      AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
                                      AWS_DEFAULT_REGION environmental variables
                                      instead of saving them to the aws
                                      configuration file.
      --role-arn TEXT                 Predefined role arn to selects, e.g. aws-
                                      adfs login --role-arn arn:aws:iam::123456789
                                      012:role/YourSpecialRole
      --session-duration INTEGER      Define the amount of seconds you want to
                                      establish your STS session, e.g. aws-adfs
                                      login --session-duration 3600
      --assertfile TEXT               Use SAML assertion response from a local
                                      file
      --sspi / --no-sspi              Whether or not to use Kerberos SSO
                                      authentication via SSPI, which may not work
                                      in some environments.
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
* duo-security
    * Error: Cannot begin authentication process. The error response: {"message": "Unknown authentication method.", "stat": "FAIL"}
    
        Please setup preferred auth method in duo-sercurity settings (settings' -> 'My Settings & Devices').
* in cases of trouble with lxml please install

  ```
  sudo apt-get install python-dev libxml2-dev libxslt1-dev zlib1g-dev
  ```
* in cases of trouble with OSX Sierra (obsolete OpenSSL), upgrade OpenSSL. Example:
  ```
  brew upgrade openssl
  ```
  AND add explicit directive to .bash_profile:
  ```
  export PATH=$(brew --prefix openssl)/bin:$PATH
  ```

* python 2.6 is not supported
* python 3.2 is not supported
* python 3.3 is not supported


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
* [roblugton](https://github.com/roblugton) for: Fix formatting in README.md
* [cliv](https://github.com/cliv) for: pointing out the issue with missing preferred device for duo-security and providing workaround
* [AndrewFarley](https://github.com/AndrewFarley) for: Bug in parsing Duo host and signature, backwards compatible
* [eikenb](https://github.com/eikenb) for: Version 0.3.4 returns no roles - thanks for vigilance of [eikenb](https://github.com/eikenb) spoiled egg was identified
* [eikenb](https://github.com/eikenb) for: add login argument to accept username/password from stdin
* [irgeek](https://github.com/irgeek) for: Add Symantec VIP Access support
* [Brandond](https://github.com/brandond) for: Fix Negotiate auth on non-domain-joined Windows hosts
* [giafar](https://github.com/giafar) for: Role arn as parameter
* [zanettibo](https://github.com/zanettibo) for: Add support for Ansible Tower/AWX workflow authentication
* [anthoneous](https://github.com/anthoneous) and [KyleJamesWalker](https://github.com/KyleJamesWalker) for: add session duration flag
* [KyleJamesWalker](https://github.com/KyleJamesWalker) for: Allow phone call authentication
* [KyleJamesWalker](https://github.com/KyleJamesWalker) for: Change default profile to default
* [kwhitlock](https://github.com/kwhitlock) for: Feature/read username and password from file
* [avoidik](https://github.com/avoidik) for: Workaround of Symantec VIP obfuscated form
* [leonardo-test](https://github.com/leonardo-test) for fix: The --env flag is not being called and therefore using the env parameter will not work.
* [NotMrSteve](https://github.com/NotMrSteve) for: Add RSA SecurID MFA
* [JLambeth](https://github.com/JLambeth) for: Added flag for disabling Kerberos SSO authentication via SSPI
* [bghinkle](https://github.com/bghinkle) for: Fix Duo API change - follow result_url and return cookie from result
* [jan-molak](https://github.com/jan-molak) for: Corrected the XPath expression to work with the latest version of AWS…
* [NotMrSteve](https://github.com/NotMrSteve) for: Save duo session cookies
* [pdecat](https://github.com/pdecat) for: Fallback on prompt if env, stdin or auth file do not provide both username and password
* [0x91](https://github.com/0x91) for: Support for Azure MFA Server
* [pdecat](https://github.com/pdecat) for: Fix Duo authentication initiation failure messages 
* [tommywo](https://github.com/tommywo) for: save provider_id config 
