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
* [duo security](https://duo.com) MFA provider with support for FIDO U2F hardware authenticator
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

* Windows 10

   - Install latest supported Visual C++ downloads from Microsoft for Visual Studio 2015, 2017 and 2019:
      - https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads
      - https://aka.ms/vs/16/release/vc_redist.x64.exe
    - Install Python 3.7 from Microsoft Store:
      - https://www.microsoft.com/en-us/p/python-37/9nj46sx7x90p
    - Start PowerShell as Administrator
    - Go to `C:\Program Files`:
        ```
        C:
        cd 'C:\Program Files\'
        ```
    - Create virtual env:
      ```
      python3 -m venv aws-adfs
      ```
    - Install `aws-adfs`:
      ```
      & 'C:\Program Files\aws-adfs\Scripts\pip' install aws-adfs
      ```
    - Run it:
      ```
      & 'C:\Program Files\aws-adfs\Scripts\aws-adfs' login --adfs-host=your-adfs-hostname
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
                                      authentication via SSPI (Windows only,
                                      defaults to True).
      --u2f-trigger-default / --no-u2f-trigger-default
                                      Whether or not to also trigger the default
                                      authentication method when U2F is available
                                      (only works with Duo for now).
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

    `Error: Cannot begin authentication process. The error response: {"message": "Unknown authentication method.", "stat": "FAIL"}`

    Please setup preferred auth method in duo-security settings (settings' -> 'My Settings & Devices').

* USB FIDO U2F does not work in Windows Subsystem for Linux (WSL)

    `OSError: [Errno 2] No such file or directory: '/sys/class/hidraw'`

    USB devices are not accessible in WSL, please install and run `aws-adfs` on the Windows 10 host and then access the credentials in WSL from the filesystem. Example:

    ```
    export AWS_CONFIG_FILE=/mnt/c/Users/username/.aws/config
    export AWS_SHARED_CREDENTIALS_FILE=/mnt/c/Users/username/.aws/credentials
    ```

*  FIDO U2F devices are not detected on Windows 10 build 1903 or newer

    Running `aws-adfs` as Administrator is required since Windows 10 build 1903 to access FIDO U2F devices, cf. https://github.com/Yubico/python-fido2/issues/55)

* in cases of trouble with lxml please install

  ```
  sudo apt-get install python-dev libxml2-dev libxslt1-dev zlib1g-dev
  ```

* in cases of trouble with pykerberos please install

  ```
  sudo apt-get install python-dev libkrb5-dev
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
* [budzejko](https://github.com/budzejko) for: Add support for adfs-ca-bundle option
* [rinrinne](https://github.com/rinrinne) for: Respect AWS_DEFAULT_PROFILE if defined
* [mjernsell](https://github.com/mjernsell) for: Add support for AzureMfaAuthentication
* [kfattig](https://github.com/kfattig) for: Handle sspi like other config options
* [pdecat](https://github.com/pdecat) for:
    * lxml 4.4.0 dropped support for python 3.4
    * Add Duo U2F support
    * Use MozillaCookieJar as LWPCookieJar has an issue on Windows when cookies have an 'expires' date too far in the future and they are converted from timestamp to datetime
    * Fix python 2.7 compatibility
    * Document Windows 10 and WSL usage/issues
    * Run tests with python 3.6, 3.7 and 3.8-dev
    * Add options to trigger or not the default authentication method when U2F is available
    * Fix AttributeError: 'generator' object has no attribute 'append' on python3
    * Do not print stack trace if no U2F device is available
    * Pin fido2 dependency to < 0.8.0 as it is a breaking release
    * U2F: fido2 v0.8.1 compatibility (U2FClient.sign timeout renamed to event)
* [bodgit](https://github.com/bodgit) for: Kerberos support
* [pdecat](https://github.com/pdecat) for: 
    * Duo: support U2F with no preferred factor or device configured
    * Document new libkrb5-dev system dependency for pykerberos 
    * Drop boto3 dependency
    * Default SSPI to True on Windows only, False otherwise
* [rheemskerk](https://github.com/rheemskerk) for:
    * Fix username and password disclosure 
    * Fix authentication with cookies on non-windows system. 