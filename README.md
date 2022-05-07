# aws-adfs
[![PyPI version](https://badge.fury.io/py/aws-adfs.svg)](https://badge.fury.io/py/aws-adfs)
[![Travis build](https://api.travis-ci.org/venth/aws-adfs.svg?branch=master)](https://api.travis-ci.org/venth/aws-adfs.svg?branch=master)
![Build Status](https://github.com/venth/aws-adfs/workflows/Build/badge.svg?branch=master)

The project provides command line tool - `aws-adfs` to ease AWS cli authentication against ADFS (multi factor authentication with active directory).

## `aws-adfs` command line tool

* allows you to re-login to STS without entering credentials for an extended period of time, without having to store the user's actual credentials. It also lets an organization control the period in which a user can re-login to STS without entering credentials, by altering the ADFS session lifetime.

* supports automation tools like ansible by providing security token in `AWS_SESSION_TOKEN`/`AWS_SECURITY_TOKEN` environment variables.

* supports using Security Support Provider Interface (SSPI) on Windows OS.

### MFA integration

aws-adfs integrates with:
* [duo security](https://duo.com) MFA provider with support for FIDO U2F (CTAP1) / FIDO2 (CTAP2) hardware authenticators
* [Symantec VIP](https://vip.symantec.com/) MFA provider
* [RSA SecurID](https://www.rsa.com/) MFA provider

# Installation

* user local installation with [pipx](https://github.com/pypa/pipx)

    ```
    pipx install aws-adfs
    ```

* user local installation with pip

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
    virtualenv aws-adfs
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

* login to your adfs host and fetch roles for AWS GovCloud (US)

    ```
    aws-adfs login --adfs-host=your-adfs-hostname --provider-id urn:amazon:webservices:govcloud --region us-gov-west-1
    ```

    and verification

    ```
    aws s3 ls
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

* .aws/config profile for automatically refreshing credentials
    ```
    [profile example-role-ue1]
    credential_process=aws-adfs login --region=us-east-1 --role-arn=arn:aws:iam::1234567891234:role/example-role --adfs-host=adfs.example.com --stdout
    ```
    Warning: see [AWS documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) about security considerations to take when sourcing credentials with an external process.

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
                                      connect to for all API calls
      --ssl-verification / --no-ssl-verification
                                      SSL certificate verification: Whether or not
                                      strict certificate verification is done,
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
      --username-password-command TEXT
                                      Read username and password from the output
                                      of a shell command (expected JSON format:
                                      `{"username": "myusername", "password":
                                      "mypassword"}`)
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
      --print-console-signin-url      Output a URL that lets users who sign in to
                                      your organization's network securely access
                                      the AWS Management Console.
      --console-role-arn TEXT         Role to assume for use in conjunction with
                                      --print-console-signin-url
      --console-external-id TEXT      External ID to pass in assume role for use
                                      in conjunction with --print-console-signin-
                                      url
      --role-arn TEXT                 Predefined role arn to selects, e.g. aws-
                                      adfs login --role-arn arn:aws:iam::123456789
                                      012:role/YourSpecialRole
      --session-duration INTEGER      Define the amount of seconds you want to
                                      establish your STS session, e.g. aws-adfs
                                      login --session-duration 3600
      --no-session-cache              Do not use AWS session cache in
                                      ~/.aws/adfs_cache/ directory.
      --assertfile TEXT               Use SAML assertion response from a local
                                      file
      --sspi / --no-sspi              Whether or not to use Kerberos SSO
                                      authentication via SSPI (Windows only,
                                      defaults to True).
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

* USB FIDO2 does not work in Windows Subsystem for Linux (WSL)

    `OSError: [Errno 2] No such file or directory: '/sys/class/hidraw'`

    USB devices are not accessible in WSL, please install and run `aws-adfs` on the Windows 10 host and then access the credentials in WSL from the filesystem. Example:

    ```
    export AWS_CONFIG_FILE=/mnt/c/Users/username/.aws/config
    export AWS_SHARED_CREDENTIALS_FILE=/mnt/c/Users/username/.aws/credentials
    ```

*  FIDO2 devices are not detected on Windows 10 build 1903 or newer

    Running `aws-adfs` as Administrator is required since Windows 10 build 1903 to access FIDO2 devices, cf. https://github.com/Yubico/python-fido2/issues/55)

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

* only python >= 3.6 to <4.0 are supported:
  - python 2.6 is not supported
  - python 2.7 is not supported
  - python 3.2 is not supported
  - python 3.3 is not supported
  - python 3.4 is not supported
  - python 3.5 is not supported

# Development

* update dependencies:
```
poetry update
```

* run unit tests:
```
poetry run pytest
```

* release:

```
poetry version patch # or minor, major, prepatch, preminor, premajor, prerelease
export CHANGELOG_GITHUB_TOKEN=$(gopass show -o pins/Github/github-changelog-generator)
docker run -it --rm -v "$(pwd)":/usr/local/src/your-app -e CHANGELOG_GITHUB_TOKEN githubchangeloggenerator/github-changelog-generator -u venth -p aws-adfs --future-release=$(poetry version -s)
git add .
git commit -m "Release $(poetry version -s)"
git tag --annotation -m "Release $(poetry version -s)" $(poetry version -s)
git push && git push --tags
```

# Changelog

See the [CHANGELOG.md](CHANGELOG.md) file, which is generated using [github-changelog-generator](https://github.com/github-changelog-generator/github-changelog-generator) and [action-github-changelog-generator](https://github.com/heinrichreimer/action-github-changelog-generator).