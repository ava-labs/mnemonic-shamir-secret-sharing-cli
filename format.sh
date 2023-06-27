#!/bin/bash

dry_run=false
while getopts n flag
do
    case "${flag}" in
        n ) dry_run=true;;
    esac
done

# If dry_run is set, clang-format will only check if the files are correctly formatted, but not modify them.
# In this case, formatting violations produce errors, which causes the CI job to fail. 
# Otherwise, clang-format will modify the files in place.
if $dry_run
then
    find -not -path "*build*" -iname *.h -o -iname *.cpp | xargs clang-format --dry-run --Werror --ferror-limit=100
else
    find -not -path "*build*" -iname *.h -o -iname *.cpp | xargs clang-format -i
fi