#!/usr/bin/env bash
# Runs govulncheck on every fleet repo at its pinned commit and keeps only the findings.
#
#   scripts/scan.sh fleet.lock.json data/scans [parallel]
#
# Needs: git, jq, Go, and govulncheck (go install golang.org/x/vuln/cmd/govulncheck@latest).
# Each repo is analysed with the toolchain its go.mod declares (GOTOOLCHAIN), so the standard
# library findings match the Go version the repo says it builds with.
set -euo pipefail

lock=$1
out=$(realpath -m "$2")
par=${3:-4}
work=${WORK:-$HOME/clearance-scan}
mkdir -p "$out" "$work"
org=$(jq -r .org "$lock")

scan_one() {
  local repo=$1 sha=$2 org=$3 out=$4 work=$5
  local dir="$work/$repo"
  [ -d "$dir/.git" ] || git clone -q --filter=blob:none "https://github.com/$org/$repo" "$dir"
  git -C "$dir" -c advice.detachedHead=false checkout -q "$sha"

  local tc v
  tc=$(awk '$1=="toolchain"{print $2}' "$dir/go.mod")
  if [ -z "$tc" ]; then
    v=$(awk '$1=="go"{print $2}' "$dir/go.mod")
    [[ $v =~ ^[0-9]+\.[0-9]+$ ]] && v="$v.0"
    tc="go$v"
  fi

  local start code
  start=$(date +%s)
  set +e
  (cd "$dir" && GOTOOLCHAIN=$tc govulncheck -format json ./... >"$work/$repo.raw.json" 2>"$work/$repo.err")
  code=$?
  set -e
  # Exit code 3 means "vulnerabilities found"; anything else non-zero is a failed scan.
  # Full OSV records, progress lines and the SBOM are dropped: the graph has the advisories already.
  jq -c 'select(.config or .finding)' "$work/$repo.raw.json" >"$out/$repo.json"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$repo" "$sha" "$tc" "$code" "$(($(date +%s) - start))" "$dir" >>"$out/_status.tsv"
  echo "$repo exit=$code toolchain=$tc secs=$(($(date +%s) - start)) findings=$(grep -c '"finding"' "$out/$repo.json" || true)"
}
export -f scan_one

: >"$out/_status.tsv"
# xargs appends "repo sha" after the fixed arguments, so they arrive as $4 and $5.
jq -r '.repos[] | "\(.repo) \(.sha)"' "$lock" |
  xargs -P "$par" -L1 bash -c 'scan_one "$4" "$5" "$1" "$2" "$3"' _ "$org" "$out" "$work"
