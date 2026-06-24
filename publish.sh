#!/usr/bin/env bash
set -euo pipefail

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
  shift
fi

version="${1:?usage: $0 [--dry-run] <version>}"

sed -i "s/0.0.0-semantic-release/${version}/g" Cargo.toml corus-core/Cargo.toml corus/Cargo.toml

cargo generate-lockfile

if [[ "${dry_run}" == true ]]; then
  cargo test --workspace --no-run
  cargo package -p corus-syscall --locked --allow-dirty
  cargo package -p corus-core --list --allow-dirty >/dev/null
  cargo package -p corus --list --allow-dirty >/dev/null
  echo "publish dry-run complete for ${version}"
  exit 0
fi

publish_crate() {
  local crate="$1"
  local attempt

  for attempt in 1 2 3 4 5; do
    if cargo publish -p "${crate}" --locked --allow-dirty; then
      return 0
    fi
    echo "cargo publish failed for ${crate}; retrying after crates.io index propagation (${attempt}/5)" >&2
    sleep "$((attempt * 20))"
  done

  cargo publish -p "${crate}" --locked --allow-dirty
}

publish_crate corus-syscall
publish_crate corus-core
publish_crate corus