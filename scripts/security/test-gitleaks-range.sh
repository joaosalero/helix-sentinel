#!/usr/bin/env bash

set -euo pipefail
umask 077

[[ "$#" -eq 2 ]] || {
  echo "Usage: $0 <gitleaks> <config>" >&2
  exit 64
}

gitleaks_bin="$(realpath "$1")"
config_path="$(realpath "$2")"
runner="$(realpath "$(dirname "$0")/run-gitleaks-range.sh")"
test_root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/helix-gitleaks-tests.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT

new_repo() {
  local path="$1"
  git init -q -b main "$path"
  git -C "$path" config user.name "Helix Security Test"
  git -C "$path" config user.email "security-test@example.invalid"
  git -C "$path" config commit.gpgsign false
  printf 'clean\n' > "$path/state.txt"
  git -C "$path" add state.txt
  git -C "$path" commit -q -m "initial"
}

write_canary() {
  local path="$1"
  local seed="$2"
  printf 'ghp_%s\n' "$(printf '%s' "$seed" | sha256sum | cut -c1-36)" > "$path"
}

expect_status() {
  local expected="$1"
  local label="$2"
  shift 2
  set +e
  "$@" > "$test_root/$label.log" 2>&1
  local actual="$?"
  set -e
  [[ "$actual" -eq "$expected" ]] || {
    echo "Test failed: $label returned $actual, expected $expected" >&2
    exit 1
  }
}

assert_redacted_findings() {
  local report="$1"
  local seed="$2"
  local log="${3:-}"
  local canary_value
  canary_value="ghp_$(printf '%s' "$seed" | sha256sum | cut -c1-36)"

  jq -e 'length > 0 and all(.[]; .Secret == "REDACTED" and (.Match | contains("REDACTED")))' "$report" >/dev/null
  if grep -Fq -- "$canary_value" "$report" ||
     { [[ -n "$log" ]] && grep -Fq -- "$canary_value" "$log"; }; then
    echo "Test failed: a synthetic control was not completely redacted" >&2
    exit 1
  fi
  unset canary_value
}

zeros="0000000000000000000000000000000000000000"

# Simple push and clean repository.
simple="$test_root/simple"
new_repo "$simple"
simple_base="$(git -C "$simple" rev-parse HEAD)"
printf 'next\n' >> "$simple/state.txt"
git -C "$simple" commit -qam "simple change"
simple_head="$(git -C "$simple" rev-parse HEAD)"
expect_status 0 simple "$runner" "$gitleaks_bin" "$config_path" push "" "$simple_base" "$simple_head" "$test_root/simple.json" "$simple"
jq -e 'length == 0' "$test_root/simple.json" >/dev/null

# Pull request with multiple commits.
printf 'two\n' >> "$simple/state.txt"
git -C "$simple" commit -qam "second change"
pr_head="$(git -C "$simple" rev-parse HEAD)"
expect_status 0 pr-multiple "$runner" "$gitleaks_bin" "$config_path" pull_request "$simple_base" "" "$pr_head" "$test_root/pr.json" "$simple"
grep -q 'exactly 2 expected commit(s)' "$test_root/pr-multiple.log"

# Secret introduced on the first-parent line before a merge.
first_parent="$test_root/first-parent"
new_repo "$first_parent"
first_base="$(git -C "$first_parent" rev-parse HEAD)"
git -C "$first_parent" switch -q -c side
printf 'side\n' >> "$first_parent/state.txt"
git -C "$first_parent" commit -qam "side change"
git -C "$first_parent" switch -q main
write_canary "$first_parent/first-parent.txt" first-parent-control
git -C "$first_parent" add first-parent.txt
git -C "$first_parent" commit -q -m "first parent finding"
git -C "$first_parent" merge -q --no-ff side -m "merge side"
first_head="$(git -C "$first_parent" rev-parse HEAD)"
expect_status 2 first-parent "$runner" "$gitleaks_bin" "$config_path" push "" "$first_base" "$first_head" "$test_root/first-parent.json" "$first_parent"
assert_redacted_findings "$test_root/first-parent.json" first-parent-control

# Secret introduced on the second parent of a merge.
second_parent="$test_root/second-parent"
new_repo "$second_parent"
second_base="$(git -C "$second_parent" rev-parse HEAD)"
git -C "$second_parent" switch -q -c side
write_canary "$second_parent/second-parent.txt" second-parent-control
git -C "$second_parent" add second-parent.txt
git -C "$second_parent" commit -q -m "second parent finding"
git -C "$second_parent" switch -q main
printf 'main\n' >> "$second_parent/state.txt"
git -C "$second_parent" commit -qam "main change"
git -C "$second_parent" merge -q --no-ff side -m "merge side"
second_head="$(git -C "$second_parent" rev-parse HEAD)"
expect_status 2 second-parent "$runner" "$gitleaks_bin" "$config_path" push "" "$second_base" "$second_head" "$test_root/second-parent.json" "$second_parent"
assert_redacted_findings "$test_root/second-parent.json" second-parent-control

# Secret introduced only while resolving a merge conflict.
resolution="$test_root/resolution"
new_repo "$resolution"
resolution_base="$(git -C "$resolution" rev-parse HEAD)"
git -C "$resolution" switch -q -c side
printf 'side\n' > "$resolution/state.txt"
git -C "$resolution" commit -qam "side conflict"
git -C "$resolution" switch -q main
printf 'main\n' > "$resolution/state.txt"
git -C "$resolution" commit -qam "main conflict"
set +e
git -C "$resolution" merge --no-ff side -m "merge conflict" >/dev/null 2>&1
merge_status="$?"
set -e
[[ "$merge_status" -ne 0 ]]
write_canary "$resolution/state.txt" resolution-only-control
git -C "$resolution" add state.txt
git -C "$resolution" commit -q -m "resolve conflict"
resolution_head="$(git -C "$resolution" rev-parse HEAD)"
expect_status 2 resolution "$runner" "$gitleaks_bin" "$config_path" push "" "$resolution_base" "$resolution_head" "$test_root/resolution.json" "$resolution"
assert_redacted_findings "$test_root/resolution.json" resolution-only-control

# Branch creation scans full reachable history.
expect_status 0 zero-before "$runner" "$gitleaks_bin" "$config_path" push "" "$zeros" "$pr_head" "$test_root/zero.json" "$simple"
grep -q 'exactly 3 expected commit(s)' "$test_root/zero-before.log"

# Branch creation detects a finding introduced in the root commit.
zero_finding="$test_root/zero-finding"
git init -q -b main "$zero_finding"
git -C "$zero_finding" config user.name "Helix Security Test"
git -C "$zero_finding" config user.email "security-test@example.invalid"
git -C "$zero_finding" config commit.gpgsign false
write_canary "$zero_finding/root.txt" root-commit-control
git -C "$zero_finding" add root.txt
git -C "$zero_finding" commit -q -m "root finding"
zero_finding_head="$(git -C "$zero_finding" rev-parse HEAD)"
expect_status 2 zero-finding "$runner" "$gitleaks_bin" "$config_path" push "" "$zeros" "$zero_finding_head" "$test_root/zero-finding.json" "$zero_finding"
grep -q 'exactly 1 expected commit(s)' "$test_root/zero-finding.log"
assert_redacted_findings "$test_root/zero-finding.json" root-commit-control

# Existing but divergent commits fail closed as an invalid ancestry range.
divergent="$test_root/divergent"
new_repo "$divergent"
git -C "$divergent" switch -q -c side
printf 'side\n' >> "$divergent/state.txt"
git -C "$divergent" commit -qam "side"
divergent_from="$(git -C "$divergent" rev-parse HEAD)"
git -C "$divergent" switch -q main
printf 'main\n' >> "$divergent/state.txt"
git -C "$divergent" commit -qam "main"
divergent_head="$(git -C "$divergent" rev-parse HEAD)"
expect_status 1 divergent-range "$runner" "$gitleaks_bin" "$config_path" push "" "$divergent_from" "$divergent_head" "$test_root/divergent.json" "$divergent"

# Missing range commits also fail closed.
expect_status 1 missing-range "$runner" "$gitleaks_bin" "$config_path" push "" "1111111111111111111111111111111111111111" "$pr_head" "$test_root/missing.json" "$simple"

# An empty valid range is a successful no-op with an empty report.
expect_status 0 no-commits "$runner" "$gitleaks_bin" "$config_path" push "" "$pr_head" "$pr_head" "$test_root/empty.json" "$simple"
jq -e 'length == 0' "$test_root/empty.json" >/dev/null

# Standalone canary remains detected and completely redacted.
canary_dir="$test_root/canary"
install -d -m 0700 "$canary_dir"
write_canary "$canary_dir/canary.txt" standalone-positive-control
expect_status 2 canary "$gitleaks_bin" dir "$canary_dir" --config "$config_path" --exit-code 2 --max-decode-depth 0 --no-banner --no-color --redact=100 --report-format json --report-path "$test_root/canary.json" --verbose
assert_redacted_findings "$test_root/canary.json" standalone-positive-control "$test_root/canary.log"

echo "Gitleaks range tests passed"
