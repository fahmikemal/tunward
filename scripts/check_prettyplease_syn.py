#!/usr/bin/env python3
"""Fail when a locked crate hands syn trees to a prettyplease built on another syn major version.

bindgen 0.73 accepts syn 2 or 3 and prettyplease 0.2 or 0.3, so Cargo can lock syn 3 next to a
prettyplease that still parses with syn 2. The build then stops inside bindgen with a trait error
about syn::File that does not point at the lock file.
"""
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def problems(lock_text):
    packages = tomllib.loads(lock_text).get("package", [])

    def resolve(reference):
        # Cargo.lock names a dependency as "name", "name version" or "name version (source)".
        name, *rest = reference.split(" ")
        return next(p for p in packages if p["name"] == name and (not rest or p["version"] == rest[0]))

    def dependency(package, name):
        return next((resolve(d) for d in package.get("dependencies", []) if d.split(" ")[0] == name), None)

    found = []
    for package in packages:
        syn, printer = dependency(package, "syn"), dependency(package, "prettyplease")
        if syn is None or printer is None:
            continue
        printer_syn = dependency(printer, "syn")
        if syn["version"].split(".")[0] != printer_syn["version"].split(".")[0]:
            crate = f'{package["name"]}@{package["version"]}'
            found.append(
                f'{crate} uses syn {syn["version"]} but its prettyplease {printer["version"]} uses syn '
                f'{printer_syn["version"]}; run `cargo update -p {crate} -p prettyplease` and check again'
            )
    return found


def main():
    found = problems((ROOT / "Cargo.lock").read_text())
    for problem in found:
        print(problem, file=sys.stderr)
    if found:
        raise SystemExit(1)
    print("every crate that prints syn trees with prettyplease shares its syn version")


if __name__ == "__main__":
    main()
