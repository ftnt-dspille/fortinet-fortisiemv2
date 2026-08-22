#!/usr/bin/env bash
# Build the connector bundle FortiSOAR installs.
#
# The tarball must unpack to a single `fortinet-fortisiemv2/` directory. Its
# contents are the git-tracked files MINUS the development-only ones below:
# packaging the working directory instead is how a 92 KB bundle becomes 14 MB,
# because `.venv/` gets swept in.
set -euo pipefail

cd "$(dirname "$0")/.."
NAME=$(python3 -c "import json;print(json.load(open('info.json'))['name'])")
VERSION=$(python3 -c "import json;print(json.load(open('info.json'))['version'])")
OUT="dist/${NAME}-${VERSION}.tgz"

# Never shipped: tests, the playbook compiler, and repo furniture. The
# appliance neither needs nor runs any of it.
EXCLUDE='^(\.github/|\.gitignore$|README\.md$|scripts/|tests/|playbooks/build\.py$|dist/)'

mapfile -t FILES < <(git ls-files | grep -Ev "$EXCLUDE")
if [ ${#FILES[@]} -eq 0 ]; then
    echo "package: no files matched -- run from a git checkout" >&2
    exit 1
fi

# info.json and the compiled playbooks are what the appliance keys on; a
# missing one produces a bundle that installs and then does nothing.
for required in info.json playbooks/playbooks.json; do
    printf '%s\n' "${FILES[@]}" | grep -qx "$required" \
        || { echo "package: $required missing from the bundle" >&2; exit 1; }
done

rm -rf dist && mkdir -p "dist/stage/${NAME}"
# Staged rather than tarred in place with a prefix option: GNU tar spells that
# --transform and bsdtar spells it -s, so a script using either breaks on the
# other. Copying into a directory named for the connector works on both.
for f in "${FILES[@]}"; do
    mkdir -p "dist/stage/${NAME}/$(dirname "$f")"
    cp "$f" "dist/stage/${NAME}/$f"
done
tar czf "$OUT" -C dist/stage "${NAME}"
rm -rf dist/stage

echo "$OUT ($(printf '%s\n' "${FILES[@]}" | wc -l | tr -d ' ') files, $(du -h "$OUT" | cut -f1))"
