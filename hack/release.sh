#!/usr/bin/env bash
# Bump every version reference, verify, commit, and tag a release.
# Pushing is left to the caller.
set -euo pipefail

new="${1:-}"
if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: make release VERSION=x.y.z" >&2
  exit 1
fi

if [ "$(git branch --show-current)" != main ]; then
  echo "releases are cut from main" >&2
  exit 1
fi
if ! git diff --quiet HEAD; then
  echo "working tree has uncommitted changes" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/v${new}" >/dev/null; then
  echo "tag v${new} already exists" >&2
  exit 1
fi

chart=charts/tlsa-dnsendpoint-controller/Chart.yaml
old=$(awk '$1=="version:"{print $2}' "$chart")
if [ "$old" = "$new" ]; then
  echo "already at ${new}" >&2
  exit 1
fi
o="${old//./\\.}"
files=("$chart" deploy/deployment.yaml README.md charts/tlsa-dnsendpoint-controller/README.md)
count() { cat "${files[@]}" | grep -cE -- "$1" || true; }
want=$(count "(version:|appVersion:|--version|:)\"?${o}")

# Anything failing before the commit leaves the tree as it was found.
committed=
trap '[ -n "$committed" ] || git checkout -- "${files[@]}"' EXIT

# Only the install commands and image tags; prose such as "upgrade to 0.2.4 or
# later" names the release a fix shipped in and must not move.
sed -i.bak -e "s/^version: ${o}\$/version: ${new}/" \
  -e "s/^appVersion: \"${o}\"\$/appVersion: \"${new}\"/" \
  -e "s/:${o}\$/:${new}/" "$chart"
sed -i.bak "s/:${o}\$/:${new}/" deploy/deployment.yaml
sed -i.bak -e "s/--version ${o} /--version ${new} /" -e "s/:${o}\`/:${new}\`/" README.md
sed -i.bak "s/--version ${o} /--version ${new} /" charts/tlsa-dnsendpoint-controller/README.md
rm -f "$chart.bak" deploy/deployment.yaml.bak README.md.bak charts/tlsa-dnsendpoint-controller/README.md.bak

got=$(count "(version:|appVersion:|--version|:)\"?${new//./\\.}")
if [ "$got" != "$want" ]; then
  echo "expected ${want} references to move to ${new}, found ${got}; check the sed patterns" >&2
  exit 1
fi

git --no-pager diff --stat
make verify

git commit -q -am "chore(release): ${new}" \
  -m "Chart version, appVersion, and the image tags and install commands in the manifests and READMEs."
committed=1
git tag -s "v${new}" -m "v${new}"

echo
echo "Tagged v${new}. Publish with:"
echo "  git push origin main v${new}"
