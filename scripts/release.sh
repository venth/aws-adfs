#!/bin/bash

VERSION=$1

set -euo pipefail

# Ensure Github token needed for changelog generation is set
: $CHANGELOG_GITHUB_TOKEN

set -x # TO COMMENT

request_approval_to_continue() {
    echo
    echo $1
    echo
    echo 'Continue with release? Only "yes" will be accepted to approve.'
    read CONTINUE
    [ "$CONTINUE" == "yes" ] || exit 0
}

show_help () {
    echo Usage: $0 VERSION
    echo
    echo VERSION should ideally be a valid semver string or a valid bump rule: patch, minor, major, prepatch, preminor, premajor, prerelease.
    exit 0
}

show_git_diff_staged() {
    echo
    echo Current staged diff:
    echo
    git diff --staged
}

# Check GNU sed
sed --version |& head -n 1 | grep "(GNU sed)" || (echo ERROR: this script requires GNU sed ; exit 1)

# Show help if needed
([ "$VERSION" == "-h" ] || [ "$VERSION" == "--help" ] || [ "$VERSION" == "" ]) && show_help

# Ensure we are on master branch (we do not backport fixes for older major versions yet)
[ "$(git rev-parse --abbrev-ref HEAD)" == "master" ] || (echo ERROR: not on "master" branch, aborting. ; exit 1)

# Ensure pyproject.toml and CHANGELOG.md do not have unstaged modifications
git diff --exit-code CHANGELOG.md &> /dev/null || (echo ERROR: CHANGELOG.md file has unstaged changes, aborting. ; exit 1)
git diff --exit-code pyproject.toml &> /dev/null || (echo ERROR: pyproject.toml file has unstaged changes, aborting. ; exit 1)

# Bump the version with poetry and re-read it
poetry version $VERSION
VERSION=$(poetry version --short)

request_approval_to_continue "New version will be: $VERSION"

# Update `CHANGELOG.md`
docker run -it --rm -v "$(pwd)":/usr/local/src/your-app -e CHANGELOG_GITHUB_TOKEN githubchangeloggenerator/github-changelog-generator -u venth -p aws-adfs --future-release=$(poetry version -s)

git add pyproject.toml CHANGELOG.md
show_git_diff_staged

request_approval_to_continue "Ready to commit"

# Commit these changes
git commit -m "Release v$VERSION"

request_approval_to_continue "Ready to create annotated tag"

# Tag with last CHANGELOG.md item content as annotation
sed '3,${/^## \[/Q}' CHANGELOG.md | git tag -a -F- v$VERSION

# Bump the version with poetry again to mark it for development
echo
echo Bump the version with poetry again to mark it for development
echo
poetry version prerelease
VERSION=$(poetry version --short)

git add pyproject.toml
show_git_diff_staged

request_approval_to_continue "Ready to commit"

# Commit this changes
git commit -m "Develop v$VERSION"

request_approval_to_continue "Ready to push to remote GitHub repository, and trigger a Github Actions job to publish packages to PyPI"

git push origin --follow-tags
