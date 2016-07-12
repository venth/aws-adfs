# aws-adfs
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
    $ aws-adfs --help                                                                                                                                                    13:37
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
    $ aws-adfs list --help                                                                                                                                               13:38
    Usage: aws-adfs list [OPTIONS]

      lists available profiles

    Options:
      --version  Show current tool version
      --help  Show this message and exit.
    ```

    ```
    $ aws-adfs login --help                                                                                                                                              13:38
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

# Credits
* [Brandond](https://github.com/brandond) for: Remove storage of credentials, in favor of storing ADFS session cookies
* [Brandond](https://github.com/brandond) for: Add support for legacy aws_security_token key in credentials file
* [Brandond](https://github.com/brandond) for: Store last username in profile config; use it as default for prompt