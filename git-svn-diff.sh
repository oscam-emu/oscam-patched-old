#!/bin/bash
# Generate an SVN-compatible diff against the tip of the tracking branch

# Get the tracking branch (if we're on a branch)
TRACKING_BRANCH=`git svn info | grep URL | sed -e 's/.*\/branches\///'`

# If the tracking branch has 'URL' at the beginning, then the sed wasn't successful
# and we'll fall back to the svn-remote config option
if [[ "$TRACKING_BRANCH" =~ URL.* ]]
then
        TRACKING_BRANCH=`git config --get svn-remote.svn.fetch | sed -e 's/.*:refs\/remotes\///'`
fi

# Get the highest revision number
REV=`git svn find-rev $(git rev-list --date-order --max-count=1 $TRACKING_BRANCH)`
#REV=`git svn info | grep 'Last Changed Rev:' | sed -E 's/^.*: ([[:digit:]]*)/\1/'`

# Then do the diff from the highest revision on the current branch and convert to SVN format
git diff --no-prefix --no-indent-heuristic $(git rev-list --date-order --max-count=1 $TRACKING_BRANCH) $* |
sed -e "/--- \/dev\/null/{ N; s|^--- /dev/null\n+++ \(.*\)|--- \1	(nonexistent)\n+++ \1	(working copy)|;n}" \
    -e "s/^--- .*/&	(revision $REV)/" \
    -e "s/^+++ .*/&	(working copy)/" \
    -e "s/^\(@@.*@@\).*/\1/" \
    -e "s/^diff --git [^[:space:]]*/Index:/" \
    -e "s/^index.*/===================================================================/" \
    -e "/^new file mode [0-9]\+$/d" \
    -e "/^deleted file mode [0-9]\+$/d"