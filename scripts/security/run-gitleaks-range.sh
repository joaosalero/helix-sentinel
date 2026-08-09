#!/usr/bin/env bash

set -euo pipefail
umask 077

usage() {
  echo "Usage: $0 <gitleaks> <config> <event> <pr-base> <push-before> <head> <report> [repository]" >&2
  exit 64
}

[[ "$#" -eq 7 || "$#" -eq 8 ]] || usage

gitleaks_bin="$1"
config_path="$2"
event_name="$3"
pr_base="$4"
push_before="$5"
head_ref="$6"
report_path="$7"
repository="${8:-.}"

[[ -x "$gitleaks_bin" ]] || { echo "Gitleaks executable is unavailable" >&2; exit 1; }
[[ -f "$config_path" ]] || { echo "Gitleaks config is unavailable" >&2; exit 1; }
[[ -d "$repository" ]] || { echo "Repository path is unavailable" >&2; exit 1; }
command -v git >/dev/null
command -v jq >/dev/null

require_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Invalid commit SHA in event payload" >&2
    exit 1
  }
}

require_commit() {
  git -C "$repository" cat-file -e "$1^{commit}" 2>/dev/null || {
    echo "Unable to resolve a required commit" >&2
    exit 1
  }
}

require_sha "$head_ref"
require_commit "$head_ref"

full_history=false
case "$event_name" in
  pull_request)
    require_sha "$pr_base"
    require_commit "$pr_base"
    from_ref="$pr_base"
    ;;
  push)
    require_sha "$push_before"
    if [[ "$push_before" =~ ^0{40}$ ]]; then
      full_history=true
      from_ref=""
    else
      require_commit "$push_before"
      from_ref="$push_before"
    fi
    ;;
  *)
    echo "Unsupported GitHub event" >&2
    exit 1
    ;;
esac

if [[ "$full_history" == false ]] &&
   ! git -C "$repository" merge-base --is-ancestor "$from_ref" "$head_ref"; then
  echo "Gitleaks range is not a fast-forward ancestry range" >&2
  exit 1
fi

work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/helix-gitleaks.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
expected_commits="$work_dir/expected-commits"
scanned_commits="$work_dir/scanned-commits"
aggregate_report="$work_dir/aggregate.json"
: > "$scanned_commits"
printf '[]\n' > "$aggregate_report"

if [[ "$full_history" == true ]]; then
  git -C "$repository" rev-list --reverse --topo-order "$head_ref" > "$expected_commits"
else
  git -C "$repository" rev-list --reverse --topo-order "$from_ref..$head_ref" > "$expected_commits"
fi

expected_count="$(wc -l < "$expected_commits" | tr -d '[:space:]')"
if [[ "$expected_count" -eq 0 ]]; then
  install -m 0600 "$aggregate_report" "$report_path"
  echo "No commits to scan"
  exit 0
fi

finding_status=0
commit_index=0
while IFS= read -r commit_sha; do
  require_sha "$commit_sha"
  require_commit "$commit_sha"
  commit_index=$((commit_index + 1))
  commit_report="$work_dir/report-$commit_index.json"
  commit_log="$work_dir/scan-$commit_index.log"

  set +e
  "$gitleaks_bin" git "$repository" \
    --config "$config_path" \
    --exit-code 2 \
    --log-opts="--no-walk --diff-merges=first-parent $commit_sha" \
    --max-decode-depth 0 \
    --no-banner \
    --no-color \
    --redact=100 \
    --report-format json \
    --report-path "$commit_report" \
    --verbose > "$commit_log" 2>&1
  scan_status="$?"
  set -e

  if [[ "$scan_status" -ne 0 && "$scan_status" -ne 2 ]]; then
    echo "Gitleaks execution failed for an expected commit" >&2
    exit "$scan_status"
  fi
  if ! grep -Eq '(^| )1 commits scanned\.$' "$commit_log"; then
    echo "Gitleaks did not confirm a single-commit scan" >&2
    exit 1
  fi
  if ! jq -e 'type == "array" and all(.[]; .Secret == "REDACTED" and (.Match | contains("REDACTED")))' "$commit_report" >/dev/null; then
    echo "Gitleaks produced an invalid or unredacted report" >&2
    exit 1
  fi

  commit_findings="$(jq 'length' "$commit_report")"
  if [[ "$scan_status" -eq 2 && "$commit_findings" -eq 0 ]] ||
     [[ "$scan_status" -eq 0 && "$commit_findings" -ne 0 ]]; then
    echo "Gitleaks exit status and report disagree" >&2
    exit 1
  fi
  if [[ "$scan_status" -eq 2 ]]; then
    finding_status=2
  fi

  next_report="$work_dir/aggregate-$commit_index.json"
  jq -s '.[0] + .[1]' "$aggregate_report" "$commit_report" > "$next_report"
  mv "$next_report" "$aggregate_report"
  printf '%s\n' "$commit_sha" >> "$scanned_commits"
done < "$expected_commits"

if ! cmp -s "$expected_commits" "$scanned_commits"; then
  echo "Gitleaks did not process the complete expected commit set" >&2
  exit 1
fi

install -m 0600 "$aggregate_report" "$report_path"
finding_count="$(jq 'length' "$aggregate_report")"
echo "Validated Gitleaks scanned exactly $expected_count expected commit(s)"

if [[ "$finding_status" -eq 2 ]]; then
  echo "Gitleaks detected $finding_count redacted finding(s)" >&2
fi
exit "$finding_status"
