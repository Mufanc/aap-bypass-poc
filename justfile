#!/usr/bin/env just --justfile

TARGET_SDK := "35"

# https://developer.android.com/ndk/guides/other_build_systems#overview
HOST_TAG := (if os() == "macos" { "darwin" } else { os() }) + "-x86_64"

CC := env("ANDROID_NDK") / "toolchains/llvm/prebuilt" / HOST_TAG / "bin" / ("aarch64-linux-android" + TARGET_SDK + "-clang")

run *ARGS:
    cargo run \
        --target aarch64-linux-android \
        --release \
        --config target.aarch64-linux-android.linker=\"{{CC}}\" \
        -- {{ARGS}}

clean:
    cargo clean
