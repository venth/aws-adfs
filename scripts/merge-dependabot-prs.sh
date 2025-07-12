#!/bin/bash

# set -x # TO REMOVE

set -euo pipefail

request_approval_to_continue() {
    echo
    echo $1
    echo
    echo 'Continue with PR approval and merge? Only "yes" will be accepted to approve.'
    read CONTINUE
    [ "$CONTINUE" == "yes" ] || exit 0
}

show_help () {
    echo Usage: $0
    echo
    echo Iterate over open and mergeable dependabot PRs to approve and merge them.
    exit 0
}

# Show help if needed
([ "${1:-}" == "-h" ] || [ "${1:-}" == "--help" ]) && show_help

# Ensure we are on master branch
[ "$(git rev-parse --abbrev-ref HEAD)" == "master" ] || (echo ERROR: not on "master" branch, aborting. ; exit 1)

while true ; do
    gh pr list --state open --label dependencies --json title,mergeable,number,updatedAt
    GH_PR=$(gh pr list --state open --label dependencies --json title,mergeable,number,updatedAt | jq -r '.[] | select(.mergeable == "MERGEABLE") | .number' | sort -n | head -n 1); echo PR \#$GH_PR ; gh pr diff $GH_PR || break

    request_approval_to_continue "Please review above diff."
    gh pr review $GH_PR --approve
    gh pr merge $GH_PR --merge --delete-branch
done

# Pull from github
git pull
