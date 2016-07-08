# aws-adfs
Command line tool to easier aws cli authentication against ADFS (multi factor authentication with active directory)

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
      --rsa-keys <FILE FILE>...       Private and public key locations used to
                                      decrypt and encrypt credentials into storage
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
* id_rsa key cannot be password protected (not now). It's used to decrypt stored user's password