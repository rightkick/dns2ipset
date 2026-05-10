#!/bin/sh
# Print a Debian-policy-compliant version derived from git state.
# Debian §5.6.12 requires Version: to begin with a digit, so we always
# produce a digit-leading string and use `+` for the local revision so
# upgrades sort sensibly: 1.2.3 < 1.2.3+5.gabcdef0 < 1.2.3+dirty.
#
#   tagged exactly:       v1.2.3                  -> 1.2.3
#   tag + N commits:      v1.2.3-5-gabcdef0       -> 1.2.3+5.gabcdef0
#   no tags ever:         abcdef0                 -> 0.0.0+git.abcdef0
#   any of the above + uncommitted changes:       ...+dirty
#
# When run outside a git checkout, prints "0.0.0".
set -e

desc=$(git describe --tags --always --dirty 2>/dev/null || true)
if [ -z "$desc" ]; then
    echo "0.0.0"
    exit 0
fi

dirty=""
case "$desc" in
    *-dirty)
        dirty="+dirty"
        desc=${desc%-dirty}
        ;;
esac

case "$desc" in
    *-*-g*)
        # tag-N-gSHA form: split into tag, N, gSHA.
        tag=${desc%-*-g*}
        n_and_sha=${desc#"$tag"-}      # N-gSHA
        n=${n_and_sha%-g*}
        sha=g${desc##*-g}
        version="${tag#v}+${n}.${sha}"
        ;;
    v[0-9]*)
        # bare tag, leading 'v'
        version="${desc#v}"
        ;;
    [0-9]*)
        # bare tag, no leading 'v'
        version="${desc}"
        ;;
    *)
        # bare abbrev SHA: never tagged.
        version="0.0.0+git.${desc}"
        ;;
esac

printf '%s%s\n' "$version" "$dirty"
