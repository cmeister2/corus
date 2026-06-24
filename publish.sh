#!/usr/bin/env bash
set -euo pipefail

dry_run=false
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=true
  shift
fi

version="${1:?usage: $0 [--dry-run] <version>}"

sed -i "s/0.0.0-semantic-release/${version}/g" Cargo.toml chorus-core/Cargo.toml chorus/Cargo.toml

cargo generate-lockfile

if [[ "${dry_run}" == true ]]; then
  cargo test --workspace --no-run
  cargo package -p chorus-syscall --locked
  cargo package -p chorus-core --list >/dev/null
  cargo package -p chorus --list >/dev/null
  echo "publish dry-run complete for ${version}"
  exit 0
fi

publish_crate() {
  local crate="$1"
  local attempt

  for attempt in 1 2 3 4 5; do
    if cargo publish -p "${crate}" --locked; then
      return 0
    fi
    echo "cargo publish failed for ${crate}; retrying after crates.io index propagation (${attempt}/5)" >&2
    sleep "$((attempt * 20))"
  done

  cargo publish -p "${crate}" --locked
}

publish_crate chorus-syscall
publish_crate chorus-core
publish_crate chorus