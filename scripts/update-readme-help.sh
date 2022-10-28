#!/bin/bash

set -xeuo pipefail

FILES=$*

update_help() {
    COMMAND=$1
    PATTERN_START=$2
    PATTERN_END=$3

    # Get help message
    HELP=$(poetry run $COMMAND)

    # Indent it
    HELP=$(echo "$HELP" | sed -r 's/^([^$])/    \1/g')

    # Escape it, see 'Escaping a MULTI-LINE string literal for use as the replacement string in sed's s/// command
    # from 'https://stackoverflow.com/a/29613573/316805
    HELP=$(echo "$HELP" | sed -e ':a' -e '$!{N;ba' -e '}' -e 's/[&/\]/\\&/g; s/\n/\\&/g')

    # Update README.md
    sed -i -r '/<!-- '$PATTERN_START' -->/,/<!-- '$PATTERN_END' -->/c\    <!-- '$PATTERN_START' -->\n    ```\n    $ '"$COMMAND"'\n'"$HELP"'\n    ```\n    <!-- '$PATTERN_END' -->' README.md
}

if [[ " ${FILES[*]} " =~ " README.md " ]] || [[ " ${FILES[*]} " =~ " aws_adfs/commands.py " ]]; then
  update_help "aws-adfs --help" AWS_HELP_START AWS_HELP_END
fi

if [[ " ${FILES[*]} " =~ " README.md " ]] || [[ " ${FILES[*]} " =~ " aws_adfs/list_profiles.py " ]]; then
    update_help "aws-adfs list --help" AWS_LIST_HELP_START AWS_LIST_HELP_END
fi

if [[ " ${FILES[*]} " =~ " README.md " ]] || [[ " ${FILES[*]} " =~ " aws_adfs/login.py " ]]; then
    update_help "aws-adfs login --help" AWS_LOGIN_HELP_START AWS_LOGIN_HELP_END
fi

if [[ " ${FILES[*]} " =~ " README.md " ]] || [[ " ${FILES[*]} " =~ " aws_adfs/reset.py " ]]; then
    update_help "aws-adfs reset --help" AWS_RESET_HELP_START AWS_RESET_HELP_END
fi
