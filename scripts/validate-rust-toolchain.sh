#!/usr/bin/env bash
set -euo pipefail

expected_version='rustc 1.97.1 (8bab26f4f 2026-07-14)'
actual_version=$(rustc --version)
if test "$actual_version" != "$expected_version"; then
  printf 'expected the release-qualified Rust toolchain %s, found: %s\n' \
    "$expected_version" "$actual_version" >&2
  exit 1
fi

# Rust 1.87 through 1.97.0 could ask LLVM's x86 backend to hoist a load through
# a poisoned enum discriminant. The resulting release-mode binary could read
# outside an Option-wrapped two-variant enum. Rust 1.97.1 carries the LLVM fix.
case "$(uname -m)" in
  x86_64|amd64)
    fixture_dir=$(mktemp -d)
    trap 'rm -rf -- "$fixture_dir"' EXIT
    cat >"$fixture_dir/enum-option-regression.rs" <<'RUST'
#![allow(dead_code)]

use std::hint::black_box;

enum Inner {
    A(u32),
    B(u32),
}

struct Big {
    _pad: u64,
    inner: Inner,
}

struct Small {
    a: u16,
    b: u16,
    _f: fn(),
}

enum Checksum {
    X(Big),
    Y(Small),
}

impl Checksum {
    fn finalize(self) -> u32 {
        match self {
            Self::X(value) => match value.inner {
                Inner::A(sum) | Inner::B(sum) => sum,
            },
            Self::Y(value) => (u32::from(value.b) << 16) | u32::from(value.a),
        }
    }
}

#[inline(never)]
fn run(value: Option<Checksum>) -> Option<u32> {
    value.map(Checksum::finalize)
}

fn main() {
    println!("{:?}", run(black_box(None)));
}
RUST
    rustc -O "$fixture_dir/enum-option-regression.rs" \
      -o "$fixture_dir/enum-option-regression"
    test "$("$fixture_dir/enum-option-regression")" = 'None'
    ;;
esac

printf 'release Rust toolchain regression check: ok (%s)\n' "$actual_version"
