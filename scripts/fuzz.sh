#!/usr/bin/env bash
# Fuzzes each target in fuzz/ for SECONDS: scripts/fuzz.sh SECONDS [TARGET...]
#
# Without a sanitizer, so it runs on the pinned stable toolchain. The targets look for panics and
# broken invariants in safe Rust, which a sanitizer would not add to. Each target keeps what it
# finds in fuzz/corpus/TARGET and writes a crashing input to fuzz/artifacts/TARGET; fuzz/seeds is
# only read. Runs every target even after a crash, and fails if any crashed.
set -euo pipefail

seconds="${1:?usage: scripts/fuzz.sh SECONDS [TARGET...]}"
shift
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
targets=("$@")
if [ "${#targets[@]}" -eq 0 ]; then
  mapfile -t targets < <(cargo fuzz list)
fi

cargo fuzz build --sanitizer none
failed=()
for target in "${targets[@]}"; do
  options=(-max_total_time="$seconds" -print_final_stats=1)
  if [ -f "fuzz/dictionaries/$target.dict" ]; then
    options+=(-dict="$root/fuzz/dictionaries/$target.dict")
  fi
  mkdir -p "fuzz/corpus/$target"
  echo "::group::$target"
  if ! cargo fuzz run --sanitizer none "$target" "$root/fuzz/corpus/$target" "$root/fuzz/seeds/$target" -- "${options[@]}"; then
    failed+=("$target")
  fi
  echo "::endgroup::"
done
if [ "${#failed[@]}" -ne 0 ]; then
  echo "crashed: ${failed[*]}" >&2
  exit 1
fi
