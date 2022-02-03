#!/bin/sh
#
# Verify that the code passes static code check
#

if [ "$NO_VERIFY" ]; then
    echo 'pre-commit hook skipped' 1>&2
    exit 0
fi

echo "--Static code analysis--"
for file in `git diff-index --cached --name-only HEAD --diff-filter=ACMR| grep ".\/.*\.[c|h]$"` ; do
    # This makes sure to check against the revision in the index (and not the checked out version).

    clang-format -i $file
done
for diffile in `git diff --name-only --diff-filter=ACMR| grep ".\/.*\.[c|h]$"` ; do
echo "================================================================================"
echo " clang-format found problems with $file"
echo
echo " Run 'git diff' to see the diff and select 'git add -u' for accept or 'git checkout -- <file>' to decline."
    #git diff $diffile
    #git checkout -- $diffile
done
echo "--Static code analysis pass--"

